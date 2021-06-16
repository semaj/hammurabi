require 'openssl'

ORIGINAL = "certs/79c40d605e887f46b6cf9089cfadbb76881314ba3fd05ee7b67fe0894503ef2c.pem"
CA_KEY = "assets/rootCA-key.pem"
CA = "assets/rootCA.pem"
NEW = %w(basicConstraints authorityKeyIdentifier subjectKeyIdentifier)

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
cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
File.open("chain.pem", "w") do |f|
	  f.puts(cert.to_pem)
	  f.puts(intermediates)
end
