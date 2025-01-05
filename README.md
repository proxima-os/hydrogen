# Hydrogen
A monolithic Unix-like kernel for the Proxima operating system

## Build instructions
Make sure all submodules are up-to-date before beginning.

Hydrogen is configured, built, and installed like any other Meson project:
```sh
meson setup builddir -Bbuildtype=release -Db_lto=true -Db_lto_mode=thin -Db_ndebug=true
meson compile -C builddir
meson install -C builddir
```

Note the use of LTO. Hydrogen relies on the use of LTO for performance. It will work without it, of course, but it is
recommended to enable LTO when building Hydrogen.
