/*
 * Copyright (C) 2008 Andrew Ayer
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

#ifndef AGWA_FILEDESC_HPP
#define AGWA_FILEDESC_HPP

#include <unistd.h>
#include <errno.h>

class filedesc {
	int		fd;

	// No copy and assignment:
#if __cplusplus >= 201103L /* C++11 */
	filedesc& operator= (const filedesc&) = delete;
	filedesc (const filedesc&) = delete;
#else
	filedesc& operator= (const filedesc&) { return *this; }
	filedesc (const filedesc&) { }
#endif
public:
	filedesc () { fd = -1; }
	explicit filedesc (int _fd) { fd = _fd; }
#if __cplusplus >= 201103L /* C++11 */
	filedesc (filedesc&& other) noexcept { fd = other.release(); }
	~filedesc () noexcept { if (fd >= 0) ::close(fd); }
#else
	~filedesc () { if (fd >= 0) ::close(fd); }
#endif

	int	get () const { return fd; }

	operator int () const { return fd; }

	filedesc&	operator= (int new_fd)
	{
		reset(new_fd);
		return *this;
	}
#if __cplusplus >= 201103L /* C++11 */
	filedesc&	operator= (filedesc&& other) noexcept
	{
		reset(other.release());
		return *this;
	}
#endif

	void	reset (int new_fd =-1)
	{
		int old_fd = fd;
		fd = new_fd;
		if (old_fd >= 0) ::close(old_fd);
	}

	int	release ()
	{
		int orig_fd = fd;
		fd = -1;
		return orig_fd;
	}

	int	close ()
	{
		int res = 0;
		if (fd >= 0) res = ::close(fd);
		fd = -1;
		return res;
	}
};

#endif
