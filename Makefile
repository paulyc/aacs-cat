all: aacs-find-vuk

src/%.o: src/%.cpp
	g++ -g -c -Icontrib/libaacs/src -Icontrib/install/include $< -o $@

aacs-find-vuk: src/main.o contrib/install/lib/libaacs.a
	g++ -o $@ $^ -Lcontrib/install/lib contrib/libaacs/src/libaacs/.libs/*.o contrib/libaacs/src/util/.libs/*.o contrib/libaacs/src/file/.libs/*.o -lgcrypt -lgpg-error

contrib: submodules libgpg-error libgcrypt libaacs

submodules:
	git submodule init
	git submodule sync
	git submodule update
	mkdir -p contrib/install

libgpg-error: contrib/install/lib/libgpg-error.a
	cd contrib/libgpg-error && \
	./autogen.sh && \
	./configure --prefix=$(PWD)/contrib/install --enable-maintainer-mode && \
	make install

libgcrypt: contrib/install/lib/libgcrypt.a
	cd contrib/libgcrypt && \
	./autogen.sh && \
	./configure --prefix=$(PWD)/contrib/install --with-libgpg-error-prefix=$(PWD)/contrib/install --enable-maintainer-mode && \
	make install

libaacs: contrib/install/lib/libaacs.a
	cd contrib/libaacs && \
	./bootstrap && \
	./configure --prefix=$(PWD)/contrib/install && \
	make install
