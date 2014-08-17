/*
 * Copyright (C) 2014 Andrew Ayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization.
 */

#include "common.hpp"
#include "util.hpp"
#include "child.hpp"
#include "dh.hpp"
#include "rsa_client.hpp"
#include "keyserver.hpp"
#include "filedesc.hpp"
#include <fstream>
#include <limits>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <vector>
#include <algorithm>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <openssl/err.h>

static volatile sig_atomic_t	is_running = 1;
static volatile sig_atomic_t	pending_sigchld = 0;		// Set by signal handler so SIGCHLD can be handled in event loop

namespace {
	struct Basic_vhost_config {
		std::map<long, bool>		ssl_options;
		std::string			ciphers;
		openssl_unique_ptr<DH>		dhgroup;
		openssl_unique_ptr<EC_KEY>	ecdhcurve;
		std::string			key_filename;
		std::string			cert_filename;
		std::string			backend_address_string;
		std::string			backend_address_port;

		bool process_param (const std::string& key, const std::string& value);
	};
	struct Vhost_config : Basic_vhost_config {
		std::string			local_address_string;
		std::string			local_address_port;
		bool				servername_set = false;
		std::string			servername;

		bool process_param (const std::string& key, const std::string& value);
		void read_config_file (std::istream& config_in);
	};

	// Config specific to parent:
	bool			run_as_daemon = false;
	std::string		pid_file;
	uint16_t		listening_port = 0;		// stored in host byte order
	unsigned int		min_spare_children = 3;		// Minimum number of children ready and waiting to accept()
	unsigned int		max_children = 100;		// Absolute maximum number of children, spare or not
	Basic_vhost_config	vhost_defaults;
	std::vector<Vhost_config> vhost_configs;

	// State specific to parent:
	bool			pid_file_created = false;
	unsigned int		num_children = 0;		// Current # of children, spare or not
	std::vector<pid_t>	spare_children;			// PIDs of children just waiting to accept
	time_t			last_failed_child_time = 0;
	unsigned int		failed_children = 0;
	std::string		temp_directory;
	pid_t			keyserver_pid = -1;

	inline unsigned int	num_spare_children () { return spare_children.size(); }

	void sigchld_handler (int signal)
	{
		(void)(signal);
		// Don't handle this event here; set an atomic flag (which is async signal safe)
		// and handle it in the main event loop
		pending_sigchld = 1;
	}

	void graceful_termination_handler (int signal)
	{
		(void)(signal);
		is_running = 0;
	}

	void init_signals ()
	{
		struct sigaction		siginfo;

		sigemptyset(&siginfo.sa_mask);
		sigaddset(&siginfo.sa_mask, SIGINT);
		sigaddset(&siginfo.sa_mask, SIGTERM);
		sigaddset(&siginfo.sa_mask, SIGCHLD);

		// SIGINT and SIGTERM
		siginfo.sa_flags = 0;
		siginfo.sa_handler = graceful_termination_handler;
		sigaction(SIGINT, &siginfo, NULL);
		sigaction(SIGTERM, &siginfo, NULL);

		// SIGCHLD
		siginfo.sa_flags = 0;
		siginfo.sa_handler = sigchld_handler;
		sigaction(SIGCHLD, &siginfo, NULL);

		// SIGPIPE
		siginfo.sa_flags = 0;
		siginfo.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &siginfo, NULL);

		// Block SIGINT, SIGTERM, SIGCHLD; they will be unblocked
		// at a convenient time
		sigprocmask(SIG_BLOCK, &siginfo.sa_mask, NULL);
	}

	struct Too_many_failed_children { };
	struct Keyserver_died { };

	void spawn_children ()
	{
		while (num_spare_children() < min_spare_children && num_children < max_children) {
			pid_t		pid = spawn(child_main);

			++num_children; // upper bounded by max_children
			spare_children.push_back(pid);
		}
	}

	// Called in the parent process when a child has accepted a connection
	void on_child_accept (pid_t pid)
	{
		std::vector<pid_t>::iterator	it(std::find(spare_children.begin(), spare_children.end(), pid));
		if (it != spare_children.end()) {
			// Such a child is no longer spare
			spare_children.erase(it);
			spawn_children();
		}
	}

	void read_children_pipe ()
	{
		ssize_t		bytes_read;
		pid_t		pid;
		while ((bytes_read = read(children_pipe[0], &pid, sizeof(pid))) == sizeof(pid)) {
			on_child_accept(pid);
		}
		if (bytes_read == -1 && errno == EAGAIN) {
			return;
		}
		if (bytes_read == -1) {
			throw System_error("read", "children_pipe[0]", errno);
		}
		throw System_error("read", "children_pipe[0]", EPROTO);
	}

	void on_child_terminated (pid_t pid, int status)
	{
		bool	failed = false;
		if (WIFSIGNALED(status)) {
			std::clog << "Child " << pid << " terminated by signal " << WTERMSIG(status) << std::endl;
			failed = true;
		} else if (!WIFEXITED(status)) {
			std::clog << "Child " << pid << " terminated uncleanly" << std::endl;
			failed = true;
		} else if (WEXITSTATUS(status) != 0) {
			std::clog << "Child " << pid << " exited with status " << WEXITSTATUS(status) << std::endl;
			failed = true;
		}

		std::vector<pid_t>::iterator	it(std::find(spare_children.begin(), spare_children.end(), pid));
		if (it != spare_children.end()) {
			spare_children.erase(it);
			if (failed) {
				++failed_children;
				last_failed_child_time = std::time(NULL);
				if (failed_children == min_spare_children * 3) {
					throw Too_many_failed_children();
				}
			}
		}

		--num_children; // won't underflow b/c every --num_children can be paired with a ++num_children

		spawn_children();
	}

	void on_sigchld ()
	{
		// This is not a signal handler. It's called from the main event loop when
		// the pending_sigchld flag is set (which is set from the signal handler).
		pid_t	child_pid;
		int	child_status;
		while ((child_pid = waitpid(-1, &child_status, WNOHANG)) > 0) {
			if (child_pid == keyserver_pid) {
				throw Keyserver_died();
			} else {
				on_child_terminated(child_pid, child_status);
			}
		}
		if (child_pid == -1) {
			throw System_error("waitpid", "", errno);
		}
	}

	void read_config_file (const std::string& path);

	int ssl_servername_cb (SSL* ssl, int*, void*)
	{
		const char*	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
		if (!servername) {
			servername = "";
		}
		for (Vhost& vhost : vhosts) {
			if (vhost.matches_servername(servername)) {
				SSL_set_SSL_CTX(ssl, vhost.ssl_ctx.get());
				active_vhost = &vhost;
				return SSL_TLSEXT_ERR_OK;
			}
		}
		std::clog << "No matching vhost for SNI name '" << servername << "'" << std::endl;
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	void init_ssl_ctx (Vhost& vhost, const Vhost_config& config)
	{
		vhost.ssl_ctx.reset(SSL_CTX_new(SSLv23_method()));
		if (!vhost.ssl_ctx) {
			throw Openssl_error(ERR_get_error());
		}
		SSL_CTX_set_mode(vhost.ssl_ctx.get(), SSL_MODE_AUTO_RETRY);
		set_ssl_options(vhost.ssl_ctx.get(), vhost_defaults.ssl_options);
		set_ssl_options(vhost.ssl_ctx.get(), config.ssl_options);

		SSL_CTX_set_tlsext_servername_callback(vhost.ssl_ctx.get(), ssl_servername_cb);

		const std::string& ciphers(coalesce(config.ciphers, vhost_defaults.ciphers));
		if (!ciphers.empty()) {
			if (SSL_CTX_set_cipher_list(vhost.ssl_ctx.get(), ciphers.c_str()) != 1) {
				throw Configuration_error("No TLS ciphers available from " + ciphers);
			}
		}
		if (DH* dhgroup = coalesce(config.dhgroup.get(), vhost_defaults.dhgroup.get())) {
			if (SSL_CTX_set_tmp_dh(vhost.ssl_ctx.get(), dhgroup) != 1) {
				throw Configuration_error("Unable to set DH parameters: " + Openssl_error::message(ERR_get_error()));
			}
		}
		if (EC_KEY* ecdhcurve = coalesce(config.ecdhcurve.get(), vhost_defaults.ecdhcurve.get())) {
			if (SSL_CTX_set_tmp_ecdh(vhost.ssl_ctx.get(), ecdhcurve) != 1) {
				throw Configuration_error("Unable to set ECDH curve: " + Openssl_error::message(ERR_get_error()));
			}
		}

		const std::string& key_filename(coalesce(config.key_filename, vhost_defaults.key_filename));
		const std::string& cert_filename(coalesce(config.cert_filename, vhost_defaults.cert_filename));

		if (access(key_filename.c_str(), R_OK) == -1) {
			throw Configuration_error("Unable to read TLS key file: " + key_filename + ": " + std::string(std::strerror(errno)));
		}
		vhost.key_filename = key_filename;

		cstdio_unique_ptr<std::FILE>	fp(std::fopen(cert_filename.c_str(), "r"));
		if (!fp) {
			throw Configuration_error("Unable to read TLS cert file: " + cert_filename + ": " + std::string(std::strerror(errno)));
		}

		// Try to read a private key from the file.  For isolation, titus doesn't allow mixing private keys
		// and certs in the same file, so if we can successfully read the private key, error out.
		if (EVP_PKEY* privkey = PEM_read_PrivateKey(fp.get(), NULL, NULL, NULL)) {
			EVP_PKEY_free(privkey);
			throw Configuration_error("TLS cert file " + cert_filename + " contains a private key");
		}
		fseek(fp.get(), 0, SEEK_SET);

		// Read the first certificate from the file, which is our certificate:
		openssl_unique_ptr<X509>	crt(PEM_read_X509_AUX(fp.get(), NULL, NULL, NULL));
		if (!crt) {
			throw Configuration_error("Unable to load TLS cert: " + Openssl_error::message(ERR_get_error()));
		}

		// Get the RSA public key from it:
		EVP_PKEY*			pubkey = X509_get_pubkey(crt.get());
		if (!pubkey) {
			throw Configuration_error("Unable to load TLS cert: malformed X509 file?");
		}

		openssl_unique_ptr<RSA>		public_rsa(EVP_PKEY_get1_RSA(pubkey));
		if (!public_rsa) {
			// not an RSA key
			throw Configuration_error("Unable to load TLS cert: does not correspond to an RSA key");
		}

		// Create a RSA private key "client"
		openssl_unique_ptr<EVP_PKEY>	privkey(rsa_client_load_private_key(vhost.id, public_rsa.get()));
		public_rsa.reset();

		// Use this private key for SSL:
		if (SSL_CTX_use_PrivateKey(vhost.ssl_ctx.get(), privkey.get()) != 1) {
			throw Openssl_error(ERR_get_error());
		}
		privkey.release(); // now owned by ssl_ctx

		// Use this certificate for SSL:
		if (SSL_CTX_use_certificate(vhost.ssl_ctx.get(), crt.get()) != 1) {
			throw Openssl_error(ERR_get_error());
		}
		crt.release(); // now owned by ssl_ctx

		// Now read the intermediate CA (chain) certificates:
		while (X509* ca_p = PEM_read_X509(fp.get(), NULL, NULL, NULL)) {
			openssl_unique_ptr<X509> ca(ca_p);
			if (SSL_CTX_add_extra_chain_cert(vhost.ssl_ctx.get(), ca.get()) != 1) {
				throw Openssl_error(ERR_get_error());
			}
			ca.release(); // now owned by ssl_ctx
		}
		const unsigned long code = ERR_get_error();
		if (!(ERR_GET_LIB(code) == ERR_LIB_PEM && ERR_GET_REASON(code) == PEM_R_NO_START_LINE)) {
			// Not simply a harmless end-of-file error
			throw Configuration_error("Unable to load TLS cert: " + cert_filename + ": " + Openssl_error::message(code));
		}
	}

	void resolve_addresses (Vhost& vhost, const Vhost_config& config)
	{
		const auto& backend_address_string(coalesce(config.backend_address_string, vhost_defaults.backend_address_string));
		const auto& backend_address_port(coalesce(config.backend_address_port, vhost_defaults.backend_address_port));

		if (transparent == TRANSPARENT_ON) {
			if (!backend_address_string.empty() || !backend_address_port.empty()) {
				throw Configuration_error("backend and backend-address cannot be specified in transparent mode");
			}
		} else {
			if (backend_address_port.empty()) {
				throw Configuration_error("No backend-port specified");
			}
			resolve_address(&vhost.backend_address, backend_address_string, backend_address_port);
		}

		if (!config.local_address_string.empty() || !config.local_address_port.empty()) {
			resolve_address(&vhost.local_address, config.local_address_string, config.local_address_port);
		}
	}

	int config_directory_filter (const struct dirent* ent)
	{
		return ent->d_name[0] != '.';
	}

	void read_config_directory (const std::string& path)
	{
		struct dirent**	namelist;
		int		n = scandir(path.c_str(), &namelist, config_directory_filter, alphasort);
		if (n < 0) {
			throw Configuration_error("Unable to read configuration directory " + path + ": " + std::strerror(errno));
		}
		std::vector<std::string>	filenames;
		for (int i = 0; i < n; ++i) {
			filenames.push_back(namelist[i]->d_name);
			free(namelist[i]);
		}
		free(namelist);
		for (auto filename(filenames.begin()); filename != filenames.end(); ++filename) {
			read_config_file(path + "/" + *filename);
		}
	}

	bool Basic_vhost_config::process_param (const std::string& key, const std::string& value)
	{
		if (key == "ciphers") {
			ciphers = value;
		} else if (key == "dhgroup") {
			openssl_unique_ptr<DH>	dh;
			// TODO: support custom DH parameters, additional pre-defined groups
			if (value == "14") {
				dh = make_dh(dh_group14_prime, dh_group14_generator);
			} else if (value == "15") {
				dh = make_dh(dh_group15_prime, dh_group15_generator);
			} else if (value == "16") {
				dh = make_dh(dh_group16_prime, dh_group16_generator);
			} else {
				throw Configuration_error("Unknown DH group `" + value + "'");
			}
			dhgroup = std::move(dh);
		} else if (key == "ecdhcurve") {
			int	nid = OBJ_sn2nid(value.c_str());
			if (nid == NID_undef) {
				throw Configuration_error("Unknown ECDH curve `" + value + "'");
			}
			openssl_unique_ptr<EC_KEY>	ecdh(EC_KEY_new_by_curve_name(nid));
			if (!ecdh) {
				throw Configuration_error("Unable to create ECDH curve: " + Openssl_error::message(ERR_get_error()));
			}
			ecdhcurve = std::move(ecdh);
		} else if (key == "compression") {
			ssl_options[SSL_OP_NO_COMPRESSION] = !parse_config_bool(value);
		} else if (key == "sslv3") {
			ssl_options[SSL_OP_NO_SSLv3] = !parse_config_bool(value);
		} else if (key == "tlsv1") {
			ssl_options[SSL_OP_NO_TLSv1] = !parse_config_bool(value);
		} else if (key == "tlsv1.1") {
			ssl_options[SSL_OP_NO_TLSv1_1] = !parse_config_bool(value);
		} else if (key == "tlsv1.2") {
			ssl_options[SSL_OP_NO_TLSv1_2] = !parse_config_bool(value);
		} else if (key == "honor-client-cipher-order") {
			ssl_options[SSL_OP_CIPHER_SERVER_PREFERENCE] = !parse_config_bool(value);
		} else if (key == "key") {
			key_filename = value;
		} else if (key == "cert") {
			cert_filename = value;
		} else if (key == "backend") {
			backend_address_string = value;
		} else if (key == "backend-port") {
			backend_address_port = value;
		} else {
			return false;
		}
		return true;
	}

	bool Vhost_config::process_param (const std::string& key, const std::string& value)
	{
		if (key == "local-address") {
			local_address_string = value;
		} else if (key == "local-port") {
			local_address_port = value;
		} else if (key == "sni-name") {
			servername_set = true;
			if (value == "\"\"") { // ""
				// treat "" as the empty server name
				servername = "";
			} else {
				servername = value;
			}
		} else {
			return Basic_vhost_config::process_param(key, value);
		}
		return true;
	}

	void process_config_param (const std::string& key, const std::string& value)
	{
		if (key == "config") {
			read_config_file(value);
		} else if (key == "config-directory") {
			read_config_directory(value);
		} else if (key == "daemon") {
			run_as_daemon = parse_config_bool(value);
		} else if (key == "pid-file") {
			pid_file = value;
		} else if (key == "port") {
			listening_port = std::atoi(value.c_str());
		} else if (key == "transparent") {
			transparent = parse_config_transparency(value);
		} else if (key == "min-spare-children") {
			min_spare_children = std::atoi(value.c_str());
		} else if (key == "max-children") {
			max_children = std::atoi(value.c_str());
		} else if (key == "max-handshake-time") {
			max_handshake_time = std::atoi(value.c_str());
		} else if (key == "network-user") {
			drop_uid_network = resolve_user(value);
		} else if (key == "network-group") {
			drop_gid_network = resolve_group(value);
		} else if (key == "keyserver-user") {
			drop_uid_keyserver = resolve_user(value);
		} else if (key == "keyserver-group") {
			drop_gid_keyserver = resolve_group(value);
		} else if (key == "chroot") {
			chroot_directory = value;
		} else {
			if (!vhost_defaults.process_param(key, value)) {
				throw Configuration_error("Unknown config parameter `" + key + "'");
			}
		}
	}

	void Vhost_config::read_config_file (std::istream& config_in)
	{
		while (config_in.good() && config_in.peek() != -1) {
			if (!std::isspace(config_in.peek()) && config_in.peek() != '#') {
				// line does not start with whitespace (and isn't a comment) => end of vhost section
				break;
			}

			// skip spaces and tabs
			while (config_in.peek() == ' ' || config_in.peek() == '\t') {
				config_in.get();
			}

			// Skip comments (lines starting with #) and blank lines
			if (config_in.peek() == '#' || config_in.peek() == '\n') {
				config_in.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				continue;
			}

			// read directive name
			std::string		directive;
			config_in >> directive;

			// skip whitespace
			config_in >> std::ws;

			// read directive value
			std::string		value;
			std::getline(config_in, value);

			if (!process_param(directive, value)) {
				throw Configuration_error("Unknown vhost parameter `" + directive + "'");
			}
		}
	}

	void read_config_file (const std::string& path)
	{
		std::ifstream	config_in(path.c_str());
		if (!config_in) {
			throw Configuration_error("Unable to open config file `" + path + "'");
		}

		while (config_in.good() && config_in.peek() != -1) {
			// Skip comments (lines starting with #) and blank lines
			if (config_in.peek() == '#' || config_in.peek() == '\n') {
				config_in.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				continue;
			}

			// read directive name
			std::string		directive;
			config_in >> directive;

			if (directive == "vhost") {
				vhost_configs.push_back(Vhost_config());
				vhost_configs.back().read_config_file(config_in);
			} else {
				// skip whitespace
				config_in >> std::ws;

				// read directive value
				std::string		value;
				std::getline(config_in, value);

				process_config_param(directive, value);
			}
		}
	}

	void cleanup ()
	{
		// only kill spare children; let other children continue to service their active connection
		// our children don't need to do any cleanup, so just use SIGKILL so we can be sure they
		// actually die
		for (size_t i = 0; i < spare_children.size(); ++i) {
			kill(spare_children[i], SIGKILL);
		}

		if (keyserver_pid != -1) {
			kill(keyserver_pid, SIGKILL);
		}

		if (pid_file_created) {
			unlink(pid_file.c_str());
		}

		if (keyserver_sockaddr.sun_path[0]) {
			unlink(keyserver_sockaddr.sun_path);
		}

		if (!temp_directory.empty()) {
			rmdir(temp_directory.c_str());
		}
	}
}

int main (int argc, char** argv)
try {
	init_signals();

	// Initialize OpenSSL
	ERR_load_crypto_strings();
	SSL_library_init();
	SSL_load_error_strings();

	// Set default SSL options, which can be overridden by config file
	vhost_defaults.ssl_options[SSL_OP_NO_COMPRESSION] = true;
	vhost_defaults.ssl_options[SSL_OP_NO_SSLv3] = true;
	vhost_defaults.ssl_options[SSL_OP_NO_TLSv1] = false;
	vhost_defaults.ssl_options[SSL_OP_NO_TLSv1_1] = false;
	vhost_defaults.ssl_options[SSL_OP_NO_TLSv1_2] = false;
	vhost_defaults.ssl_options[SSL_OP_CIPHER_SERVER_PREFERENCE] = true;

	// These can't be overriden by config file:
	vhost_defaults.ssl_options[SSL_OP_SINGLE_DH_USE] = true;
	vhost_defaults.ssl_options[SSL_OP_SINGLE_ECDH_USE] = true;
	vhost_defaults.ssl_options[SSL_OP_NO_SSLv2] = true;

	// Command line arguments come in pairs of the form "--name value" and correspond
	// directly to the name/value option pairs in the config file (a la OpenVPN).
	for (int i = 1; i < argc; ) {
		if (std::strncmp(argv[i], "--", 2) == 0 && i + 1 < argc) {
			process_config_param(argv[i] + 2, argv[i+1]);
			i += 2;
		} else {
			std::clog << argv[0] << ": Bad arguments" << std::endl;
			return 2;
		}
	}

	if (vhost_configs.empty()) {
		// No vhosts specified, so add one implicitly that matches all local addresses / SNI names.
		// It will use the options from vhost_defaults.
		vhost_configs.emplace_back();
	}

	for (size_t i = 0; i < vhost_configs.size(); ++i) {
		vhosts.emplace_back();
		Vhost&		vhost(vhosts.back());
		Vhost_config&	config(vhost_configs[i]);

		vhost.id = i;
		vhost.servername_set = config.servername_set;
		vhost.servername = config.servername;
		init_ssl_ctx(vhost, config);
		resolve_addresses(vhost, config);
	}
	// Free up some memory that's no longer needed:
	vhost_configs.clear();
	vhost_defaults = Basic_vhost_config();

	// Listen
	listening_sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (listening_sock == -1) {
		throw System_error("socket", "", errno);
	}
	set_reuseaddr(listening_sock);
	set_not_v6only(listening_sock);
	if (transparent == TRANSPARENT_ON) {
		set_transparent(listening_sock);
	}

	// TODO: support binding to specific IP addresses
	struct sockaddr_in6	listening_address;
	std::memset(&listening_address, '\0', sizeof(listening_address));
	listening_address.sin6_family = AF_INET6;
	listening_address.sin6_addr = in6addr_any;
	listening_address.sin6_port = htons(listening_port);
	if (bind(listening_sock, reinterpret_cast<const struct sockaddr*>(&listening_address), sizeof(listening_address)) == -1) {
		throw System_error("bind", "", errno);
	}

	if (listen(listening_sock, SOMAXCONN) == -1) {
		throw System_error("listen", "", errno);
	}

	// Set up UNIX domain socket for communicating with the key server.
	// Put it in a temporary directory with restrictive permissions so
	// other users can't traverse its path.  We have to use a named
	// socket as opposed to a socketpair because we need every child process
	// to communicate with the key server using its own socket.  (Duping one
	// end of a socketpair wouldn't work because then every child would
	// be referring to the same underlying socket, which provides
	// insufficient isolation.)
	temp_directory = make_temp_directory();
	filedesc keyserver_sock(make_unix_socket(temp_directory + "/server.sock", &keyserver_sockaddr, &keyserver_sockaddr_len));
	if (listen(keyserver_sock, SOMAXCONN) == -1) {
		throw System_error("listen", "", errno);
	}

	// Write PID file, daemonize, etc.
	std::ofstream		pid_file_out;
	if (!pid_file.empty()) {
		// Open PID file before forking so we can report errors
		pid_file_out.open(pid_file.c_str(), std::ofstream::out | std::ofstream::trunc);
		if (!pid_file_out) {
			throw Configuration_error("Unable to open PID file " + pid_file + " for writing.");
		}
		pid_file_created = true;
	}
	if (run_as_daemon) {
		daemonize();
	}
	if (pid_file_out) {
		pid_file_out << getpid() << '\n';
		pid_file_out.close();
	}

	// Spawn the master key server process
	keyserver_pid = spawn(keyserver_main, std::move(keyserver_sock));

	// Spawn spare children to accept() and service connections
	if (pipe(children_pipe) == -1) {
		throw System_error("pipe", "", errno);
	}
	set_nonblocking(children_pipe[0], true);

	spawn_children();

	// Wait for signals and readability on children_pipe
	sigset_t		empty_sigset;
	sigemptyset(&empty_sigset);
	fd_set			readfds;
	FD_ZERO(&readfds);
	FD_SET(children_pipe[0], &readfds);

	is_running = 1;
	struct timespec		timeout = { 2, 0 };
	int			select_res = 0;
	while (is_running && ((select_res = pselect(children_pipe[0] + 1, &readfds, NULL, NULL, failed_children ? &timeout : NULL, &empty_sigset)) >= 0 || errno == EINTR)) {
		if (failed_children && std::time(NULL) >= last_failed_child_time + 2) {
			failed_children = 0;
		}
		if (pending_sigchld) {
			on_sigchld();
			pending_sigchld = 0;
		}
		if (select_res > 0) {
			read_children_pipe();
		}
		FD_SET(children_pipe[0], &readfds);
	}

	if (is_running && select_res == -1) {
		throw System_error("pselect", "", errno);
	}


	cleanup();
	return 0;
} catch (const System_error& error) {
	std::clog << "titus: System error: " << error.syscall;
	if (!error.target.empty()) {
		std::clog << ": " << error.target;
	}
	std::clog << ": " << std::strerror(error.number) << std::endl;
	cleanup();
	return 3;
} catch (const Openssl_error& error) {
	std::clog << "titus: OpenSSL error: " << error.message() << std::endl;
	cleanup();
	return 4;
} catch (const Configuration_error& error) {
	std::clog << "titus: Configuration error: " << error.message << std::endl;
	cleanup();
	return 5;
} catch (const Too_many_failed_children& error) {
	// TODO: better error reporting when this happens
	std::clog << "titus: Too many child processes failed." << std::endl;
	cleanup();
	return 7;
} catch (const Keyserver_died& error) {
	// TODO: better error reporting when this happens
	std::clog << "titus: Key server died." << std::endl;
	cleanup();
	return 8;
}
