# Hydrogen
The kernel of the Proxima operating system

## Build instructions
Make sure all submodules are up-to-date before beginning.

Hydrogen is configured, built, and installed like any other Meson project:
```sh
meson setup builddir -Dbuildtype=release -Db_lto=true -Db_lto_mode=thin -Db_ndebug=true
meson compile -C builddir
meson install -C builddir
```

Note the use of LTO. Hydrogen relies on LTO for performance. It will work without it, of course, but the performance impact will be greater than with most projects.
