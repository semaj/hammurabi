require 'descriptive_statistics'
require 'openssl'

# Non-benchmarking Usage:
# ruby scripts/acc-test.rb <short name of acc script>
# where <short name of acc script> would be `tmp` corresponding to
# the prolog file `prolog/static/tmp.pl`.

SCRIPT_NAME = ARGV[0] || "tmp"
SHOULD_BENCHMARK = ARGV[1] || false

ORIGINAL = "certs/79c40d605e887f46b6cf9089cfadbb76881314ba3fd05ee7b67fe0894503ef2c.pem"
CA_KEY = "assets/rootCA-key.pem"
CA = "assets/rootCA.pem"
NEW = %w(basicConstraints authorityKeyIdentifier subjectKeyIdentifier)

if SHOULD_BENCHMARK == "true"
  accs = %w(name-constraints fresh-staple lifetime)
else
  accs = [SCRIPT_NAME]
end
accs.each do |acc_short|

  puts acc_short
  acc = File.read("prolog/static/#{acc_short}.pl")

  ca_key = OpenSSL::PKey.read(File.read(CA_KEY))
  ca = OpenSSL::X509::Certificate.new(File.read(CA))
  raw = File.read(ORIGINAL)
  intermediates = raw.split("-----END CERTIFICATE-----\n").reverse.drop(1).reverse.join("-----END CERTIFICATE-----\n") +  "-----END CERTIFICATE-----\n"
  cert = OpenSSL::X509::Certificate.new(raw)
  cert.not_before = Time.new(2002)
  cert.not_after = Time.new(2003)
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

  if SHOULD_BENCHMARK == "true"
    translation_times = []
    prolog_times = []
    50.times do
      output = `MOCK=true ./scripts/custom.sh /tmp/tmp.pem jameslarisch.com #{SCRIPT_NAME} --staple`
      prolog_times << output.match(/Prolog execution time: (\d+)ms/)[1].to_i
      translation_times << output.match(/Translation time: (\d+)ms/)[1].to_i
    end
    puts "#{prolog_times.mean}, #{translation_times.mean}"
  else
    system("MOCK=true ./scripts/custom.sh /tmp/tmp.pem jameslarisch.com #{SCRIPT_NAME} --staple")
  end
end
