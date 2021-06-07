require 'descriptive_statistics'
require 'openssl'

ORIGINAL = "certs/79c40d605e887f46b6cf9089cfadbb76881314ba3fd05ee7b67fe0894503ef2c.pem"
CA_KEY = "assets/rootCA-key.pem"
CA = "assets/rootCA.pem"
NEW = %w(basicConstraints authorityKeyIdentifier subjectKeyIdentifier)

#acc_short = ARGV[0]
%w(name-constraints fresh-staple lifetime).each do |acc_short|

  puts acc_short
  acc = File.read("datalog/static/#{acc_short}.pl")

  ca_key = OpenSSL::PKey.read(File.read(CA_KEY))
  ca = OpenSSL::X509::Certificate.new(File.read(CA))
  raw = File.read(ORIGINAL)
  intermediates = raw.split("-----END CERTIFICATE-----\n").reverse.drop(1).reverse.join("-----END CERTIFICATE-----\n") +  "-----END CERTIFICATE-----\n"
  cert = OpenSSL::X509::Certificate.new(raw)
  cert.not_before = Time.now
  cert.not_after = Time.now + 365 * 24 * 60 * 60
  cert.issuer = ca.subject

  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = ca
  cert.extensions = cert.extensions.select { |x| !NEW.include?(x.oid) }
  cert.add_extension(ef.create_extension("basicConstraints","CA:FALSE", true))
  cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
  cert.add_extension ef.create_extension("authorityKeyIdentifier",
                                         "keyid:always,issuer:always")
  cert.add_extension(OpenSSL::X509::Extension.new("1.3.3.7", acc, true))

  cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
  File.open("/tmp/tmp.pem", "w") do |f|
    f.puts(cert.to_pem)
  end
  system("cp #{ORIGINAL} /tmp/real.pem")
  #File.open("/tmp/real-issuer.pem", "w") do |f|
  #f.puts(intermediates)
  #end
  #system("./scripts/custom.sh /tmp/tmp.pem jameslarisch.com tmp --staple")
  translation_times = []
  datalog_times = []
  50.times do
    output = `MOCK=true ./scripts/custom.sh /tmp/tmp.pem jameslarisch.com tmp --staple`
    datalog_times << output.match(/Datalog execution time: (\d+)ms/)[1].to_i
    translation_times << output.match(/Translation time: (\d+)ms/)[1].to_i
  end
  puts "#{datalog_times.mean}, #{translation_times.mean}"
end
