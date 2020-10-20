require "os"
--opkey = require "openssl".pkey

local function unequal(literal)
  return function(s, v)
    if v then
      return nil
    else
      local x = literal[1]
      local y = literal[2]
      if x:is_const() and y:is_const() then
        if x.id == y.id then
          return nil
        else
          return {x.id,y.id}
        end
      else
        return nil
      end
    end
  end
end
datalog.add_iter_prim("ext:unequal", 2, unequal)

local function equal(literal)
  return function(s, v)
    if v then
      return nil
    else
      local x = literal[1]
      local y = literal[2]
      if x:is_const() and y:is_const() then
        if x.id == y.id then
          return {x.id,y.id}
        else
          return nil
        end
      else
        return nil
      end
    end
  end
end
datalog.add_iter_prim("ext:equal", 2, equal)


local function larger(literal)
  return function(s, v)
    if v then
      return nil
    else
      local x = literal[1]
      local y = literal[2]
      if x:is_const() and y:is_const() then
        local j = tonumber(x.id)
        local k = tonumber(y.id)
        if j and k and j > k then
          return {j, k}
        else
          return nil
        end
      elseif x:is_const() then
        local k = tonumber(x.id)
        return {k, k-1}
      elseif y:is_const() then
        local j = tonumber(y.id)
        return {j+1, j}
      else
        return nil
      end
    end
  end
end
datalog.add_iter_prim("ext:larger", 2, larger)

local function geq(literal)
  return function(s, v)
    if v then
      return nil
    else
      local x = literal[1]
      local y = literal[2]
      if x:is_const() and y:is_const() then
        local j = tonumber(x.id)
        local k = tonumber(y.id)
        if j >= k then
          return {j, k}
        else
          return nil
        end
      elseif x:is_const() then
        local k = tonumber(x.id)
        return {k, k-1}
      elseif y:is_const() then
        local j = tonumber(y.id)
        return {j+1, j}
      else
        return nil
      end
    end
  end
end
datalog.add_iter_prim("ext:geq", 2, geq)


local function add(literal)
   return function(s, v)
     if v then
        return nil
     else
        local x = literal[1]
        local y = literal[2]
        local z = literal[3]
        if y:is_const() and z:is_const() then
           local j = tonumber(y.id)
           local k = tonumber(z.id)
           if j and k then
              return {j + k, j, k}
           else
              return nil
           end
        elseif x:is_const() and z:is_const() then
           local i = tonumber(x.id)
           local k = tonumber(z.id)
           if i and k then
              return {i, i - k, k}
           else
              return nil
           end
        elseif x:is_const() and y:is_const() then
           local i = tonumber(x.id)
           local j = tonumber(y.id)
           if i and j then
              return {i, j, i - j}
           else
              return nil
           end
        else
           return nil
        end
     end
  end
end
datalog.add_iter_prim("ext:add", 3, add)

local function subtract(literal)
   return function(s, v)
     if v then
        return nil
     else
        local x = literal[1]
        local y = literal[2]
        local z = literal[3]
        if y:is_const() and z:is_const() then
           local j = tonumber(y.id)
           local k = tonumber(z.id)
           if j and k then
              return {j - k, j, k}
           else
              return nil
           end
        elseif x:is_const() and z:is_const() then
           local i = tonumber(x.id)
           local k = tonumber(z.id)
           if i and k then
              return {i, i + k, k}
           else
              return nil
           end
        elseif x:is_const() and y:is_const() then
           local i = tonumber(x.id)
           local j = tonumber(y.id)
           if i and j then
              return {i, j, i + j}
           else
              return nil
           end
        else
           return nil
        end
     end
  end
end
datalog.add_iter_prim("ext:subtract", 3, subtract)



local function s_endswith(literal)
   return function(s, v)
     if v then
        return nil
     else
        local x = literal[1]
        local y = literal[2]
        if x:is_const() and y:is_const() then
           local j = x.id
           local k = y.id
           if j and k and (k == "" or j:sub(-#k) == k) then
               return {j, k}
           else
              return nil
           end
        else
           return nil
        end
     end
  end
end
datalog.add_iter_prim("ext:s_endswith", 2, s_endswith)


local function s_startswith(literal)
   return function(s, v)
     if v then
        return nil
     else
        local x = literal[1]
        local y = literal[2]
        if x:is_const() and y:is_const() then
           local j = x.id
           local k = y.id
           if j and k and j:sub(1, #k) == k then
               return {j, k}
           else
              return nil
           end
        else
           return nil
        end
     end
  end
end
datalog.add_iter_prim("ext:s_startswith", 2, s_startswith)

function escape_pattern(text)
    return text:gsub("([^%w])", "%%%1")
end

local function s_occurrences(literal)
   return function(s, v)
     if v then
        return nil
     else
        local str = literal[1]
        local ch = literal[2]
        local n = literal[3]
        if str:is_const() and ch:is_const() then
           local j = str.id
           local k = ch.id
           _, obs = j:gsub(escape_pattern(k), "")
           return {j, k, obs}
        else
           return nil
        end
     end
  end
end
datalog.add_iter_prim("ext:s_occurrences", 3, s_occurrences)


local function s_containstldwildcard(literal)
  return function(s, v)
    if v then
       return nil
    else
        local w = literal[1]
        if w:is_const() then
            local j = w.id
            -- Imagine we matched on all public suffixes here.
            if string.match(j, '.*%*%.gov%.me') then
              return {j}
            else
              return nil
            end
        else
            return nil
        end
    end
  end
end

datalog.add_iter_prim("ext:s_containstldwildcard", 1, s_containstldwildcard)


local function s_substring(literal)
  return function(s, v)
    if v then
       return nil
    else
        local w = literal[1]
        local x = literal[2]
        local y = literal[3]
        local z = literal[4]
        if w:is_const() and x:is_const() and y:is_const() then
            local j = w.id
            local k = x.id
            local l = y.id
            return {j, k, l, string.sub(j, k + 1, #j - l)}
        else
            return nil
        end
    end
end
end
datalog.add_iter_prim("ext:s_substring", 4, s_substring)


local function b_lshift(literal)
   return function(s, v)
     if v then
        return nil
     else
        local x = literal[1]
        local y = literal[2]
        local z = literal[3]
        if y:is_const() and z:is_const() then
           local j = tonumber(y.id)
           local k = tonumber(z.id)
           if j and k then
              return {j << k, j, k}
           else
              return nil
           end
        else
           return nil
        end
     end
  end
end
datalog.add_iter_prim("ext:b_lshift", 3, b_lshift)

local function b_and(literal)
   return function(s, v)
     if v then
        return nil
     else
        local x = literal[1]
        local y = literal[2]
        local z = literal[3]
        if y:is_const() and z:is_const() then
           local j = tonumber(y.id)
           local k = tonumber(z.id)
           if j and k then
              return {j & k, j, k}
           else
              return nil
           end
        else
           return nil
        end
     end
  end
end
datalog.add_iter_prim("ext:b_and", 3, b_and)

local function now(literal)
   return function(s, v)
     if v then
        return nil
     else
      return {1601603624}
     end
  end
end
datalog.add_iter_prim("ext:now", 1, now)

local function tohex(b)
    local x = ""
    for i = 1, #b do
        x = x .. string.format("%.2x", string.byte(b, i))
    end
    return x
end

local function fromhex(str)
    local x = ""
    for i = 1, #str - 1, 2 do
        x = x .. string.char(tonumber(string.sub(str, i, i+1), 16))
    end
    return x
end

-- local function sign_valid(literal)
--    -- Candidates digests (values for algo) include "sha256", "md4" etc.
--    -- Behind the scenes, verify() calls EVP_get_digestbyname() (https://www.openssl.org/docs/man1.1.0/man3/EVP_get_digestbyname.html)
--    -- The full list of supported digests vary by the OpenSSL environment
--    -- Here is a way to get that list: https://stackoverflow.com/questions/47476427/get-a-list-of-all-supported-digest-algorithms
--    return function(s, v)
--      if v then
--         return nil
--      else
--         local sign = literal[1]
--         local key = literal[2]
--         local data = literal[3]
--         local algo = literal[4]
--         if sign:is_const() and key:is_const() and data:is_const() and algo:is_const() then
--            pk = opkey.read(key.id, false, "pem")
--            sn = fromhex(sign.id)
--            works = pk:verify(data.id, sn, algo.id)
--            if works then
--                return {sign.id, key.id, data.id, algo.id}
--            else
--                return nil
--            end
--         else
--            return nil
--         end
--      end
--   end
-- end
-- datalog.add_iter_prim("ext:sign_valid", 4, sign_valid)
