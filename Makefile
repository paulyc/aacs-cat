#    Makefile
#
#    aacs-cat - decrypt aacs mpeg2 transport stream given volume key or
#               volume id+media key block
#
#    Copyright (C) 2019 Paul Ciarlo <paul.ciarlo@gmail.com>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

all: aacs-cat

clean:
	rm -f src/*.o
	rm -f aacs-cat

distclean: clean
	rm -rf contrib/install

src/%.o: src/%.cpp contrib
	g++ -g -c -Icontrib/libaacs/src -Icontrib/install/include $< -o $@

aacs-cat: src/main.o contrib/install/lib/libaacs.a contrib/install/lib/libgcrypt.a contrib/install/lib/libgpg-error.a
	g++ -Wl,-rpath -Wl,contrib/install/lib -o $@ $^

contrib: contrib/install/lib/libgpg-error.a contrib/install/lib/libgcrypt.a contrib/install/lib/libaacs.a

contrib/install/lib/libgpg-error.a:
	cd contrib/libgpg-error && \
	./autogen.sh && \
	./configure --enable-static=yes --enable-shared=no --prefix=$(PWD)/contrib/install --enable-maintainer-mode && \
	make install

contrib/install/lib/libgcrypt.a: contrib/install/lib/libgpg-error.a
	cd contrib/libgcrypt && \
	./autogen.sh && \
	./configure --enable-static=yes --enable-shared=no --prefix=$(PWD)/contrib/install --with-libgpg-error-prefix=$(PWD)/contrib/install --enable-maintainer-mode && \
	make install

contrib/install/lib/libaacs.a: contrib/install/lib/libgcrypt.a
	cd contrib/libaacs && \
	./bootstrap && \
	./configure --prefix=$(PWD)/contrib/install && \
	make install
