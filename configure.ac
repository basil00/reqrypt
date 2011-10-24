# configure.ac
# (C) 2010, all rights reserved,
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT(reqrypt, 1.0)
AC_SUBST(PACKAGE_NAME_LONG, "ReQrypt")
AC_SUBST(PACKAGE_VERSION, "1.0")
AC_SUBST(PACKAGE_VERSION_SHORT, "1.0")

error=no
server=yes

AC_PROG_CC([], [true], [error=yes])
AC_PROG_CC_C99

if test "$ac_cv_prog_cc_c99" = "no"
then
    AC_MSG_NOTICE([*** compiler does not support C99.])
    error=yes
fi

AC_CHECK_FILE(/usr/include/linux/netfilter.h, [true], [error=yes])
AC_CHECK_FILE(/usr/include/linux/netfilter/nfnetlink.h, [true], [error=yes])
AC_CHECK_FILE(/usr/include/linux/netfilter/nfnetlink_queue.h, [true],
    [error=yes])
AC_CHECK_FILE(/usr/include/linux/netlink.h, [true], [error=yes])
AC_CHECK_HEADER(pthread.h, [true], [error=yes])
AC_CHECK_HEADER(gmp.h, [true], [server=no])
AC_CHECK_HEADER(openssl/rsa.h, [true], [server=no])

if test "$error" = "yes"
then
    AC_MSG_NOTICE([*** correct the above errors first ***])
    exit 1;
fi

if test "$server" = "no"
then
    AC_MSG_NOTICE([*** WARNING: missing SSL or GMP -- cannot build server ***])
fi

case `uname -m` in
    i?86)
        AC_SUBST(BITS, 32)
        AC_SUBST(ARCH, x86)
        ;;
    *)
        AC_SUBST(BITS, 64)
        AC_SUBST(ARCH, amd64)
        ;;
esac

AC_SUBST(ROOT, `pwd`)
AC_SUBST(PLATFORM_CAPS, LINUX)
AC_SUBST(PLATFORM, linux)

AC_OUTPUT([cfg.mk src/cfg.h src/tools/init.d.sh])

