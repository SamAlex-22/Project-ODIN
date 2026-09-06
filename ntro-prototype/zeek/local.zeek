@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl

redef Log::default_writer = Log::WRITER_ASCII;
redef LogAscii::use_json = T;
