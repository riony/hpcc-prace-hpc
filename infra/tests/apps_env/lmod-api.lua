-- Test stand-in for the part of Lmod's modulefile API that roles/apps_env's modulefiles use (T88).
-- Not Lmod: Lmod 8.7.65 itself is in the images, but neither EPEL nor its source was reachable
-- where these tests were written. Evaluates one modulefile and prints POSIX shell to stdout
-- (export lines in load mode); LmodError prints Lmod's message to stderr and exits 1.
--   lua lmod-api.lua load|unload MODULEFILE
local how, file = arg[1], arg[2]
local out = {}
local function q(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function test(flag, p) return os.execute("test " .. flag .. " " .. q(p)) == true end
function mode() return how end
function help(...) end
function whatis(...) end
function family(name) out[#out + 1] = "export LMOD_FAMILY_" .. name:upper() .. "=" .. q(file) end
function isDir(p) return test("-d", p) end
function isFile(p) return test("-f", p) end
function pathJoin(...) return (table.concat({...}, "/"):gsub("//+", "/")) end
function LmodError(...)
  io.stderr:write("Lmod has detected the following error: " .. table.concat({...}) .. "\n")
  os.exit(1)
end
function setenv(var, value)
  if how == "load" then out[#out + 1] = "export " .. var .. "=" .. q(value) end
end
function prepend_path(var, value)
  if how == "load" then out[#out + 1] = "export " .. var .. "=" .. q(value) .. "${" .. var .. ":+:$" .. var .. "}" end
end
dofile(file)
print(table.concat(out, "\n"))
