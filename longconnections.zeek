@load base/protocols/conn

module LongConnection;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		LongConnection::found
	};

	const duration: interval = 12hr &redef;
}

event connection_established(c: connection)
	{
	ConnThreshold::set_duration_threshold(c, duration);
	}

event ConnThreshold::duration_threshold_crossed(c: connection, threshold: interval, is_orig: bool)
  {
	local message = fmt("%s:%s -> %s:%s remained alive for longer than %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, threshold);

	NOTICE([$note=LongConnection::found,
		        $msg=message,
		        $sub=fmt("%.2f", threshold),
		        $conn=c]);

  }
