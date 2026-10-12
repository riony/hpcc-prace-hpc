# Test stand-in for Lmod's `module` shell function (T88; see lmod-api.lua): use, -t avail, load,
# purge. Installed as /etc/profile.d/modules.sh in the stand-in image (standin.sh), Lmod's own file in
# the Slinky images, so the /apps profile snippet is tested in its real order. Not Lmod.
module() {
  local d m f s
  case $1 in
    use) MODULEPATH=$2${MODULEPATH:+:$MODULEPATH}; export MODULEPATH ;;
    -t) [ "$2" = avail ] || return 1
        for d in ${MODULEPATH//:/ }; do echo "$d:"; (cd "$d" 2>/dev/null && find . -name '*.lua' | sed 's|^\./||; s|\.lua$||' | sort); done >&2 ;;
    load) shift
          for m; do
            f=; for d in ${MODULEPATH//:/ }; do [ -f "$d/$m.lua" ] && { f=$d/$m.lua; break; }; done
            [ -n "$f" ] || { echo "Lmod has detected the following error: unknown module $m" >&2; return 1; }
            s=$(lua /usr/local/share/prace-test/lmod-api.lua load "$f") || return 1
            eval "$s"
          done ;;
    purge|unload) ;;
    *) return 1 ;;
  esac
}
export -f module
