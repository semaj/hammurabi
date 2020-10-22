require 'uri'
require 'net/http'

#sha256 = "d6bfa0584db109b948f9b8f880abb13e30a7395dbfb600f9106b0999a6a5737b"
sha256 = ARGV[0] || (raise "must provide sha256 of leaf")

uri = URI("https://crt.sh/?q=#{sha256}")
body = Net::HTTP.get(uri)

crtsh_id = body.match(/\?id\=(\d+)/)[1]

uri = URI("https://crt.sh/?d=#{crtsh_id}")
leaf_pem = Net::HTTP.get(uri)

uri = URI('https://whatsmychaincert.com/generate')
res = Net::HTTP.post_form(
  uri,
  'include_leaf' => '1',
  'pem' => leaf_pem,
  'submit_btn' => "Generate Chain",
)
puts res.body
