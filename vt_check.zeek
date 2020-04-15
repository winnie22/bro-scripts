@load base/files/extract
@load base/files/hash

module VTCHECK;

# This module checks file hashes (sha256) against VT database. File type can be configured
# in check_file_types. Module is based on soosie (sooshie@gmail.com) great work. Tested
# on bro 2.5.

export {
        const check_file_types: set[string] = {
                "application/x-executable",
		"application/x-dosexec",
        } &redef;

        const curl: string = "/usr/bin/curl" &redef;
        const url: string = "https://www.virustotal.com/vtapi/v2/file/report";
        const user_agent = "Bro VirusTotal Checker (thanks for being awesome)"  &redef;

	const vt_apikey: vector of string &redef;

        redef enum Notice::Type += { VirusTotal::Result };
}

global checked_hashes: set[string] &synchronized;

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( meta?$mime_type && meta$mime_type in check_file_types )
        {
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
        }
    }

event file_state_remove(f: fa_file)
    {
    if ( ! f?$info ) return;

    if ( f$info?$sha256 && ! ( f$info$sha256 in checked_hashes ) )
        {
	local vt_rand: int;
	local tmp_vt_apikey: string;

        add(checked_hashes[f$info$sha256]);
        local bodyfile = fmt("%s.txt", f$info$sha256);
	vt_rand = rand(|vt_apikey|-1);
	tmp_vt_apikey = vt_apikey[vt_rand];

	local cmd = fmt("%s --connect-timeout 30 --request POST -s -k -A \"%s\" -o \"%s\" -d resource=%s -d apikey=%s \"%s\"", curl, user_agent, bodyfile, f$info$sha256, tmp_vt_apikey, url);
        when ( local result = Exec::run([$cmd=cmd, $read_files=set(bodyfile)]))
	{
            if ( result?$files && bodyfile in result$files )
                {
                local body = fmt("%s", result$files[bodyfile]);
                local context = "";
                local subcon = "-";
                if ( |body| > 0 )
                    {
		    #print body;
                    local positives: string;
                    local total: string;
                    local elements = split_string(body, /,/);
                    local results: vector of string;
		    local response: string;
                    for ( e in elements )
                        {
			#print elements[e];
                        local temp: string_vec;
			if ( /\"response_code\":/ in elements[e])
			    {
			    temp = split_string(elements[e], /:/);
			    response = "r" + temp[1];
			    }
                        else if ( /\"positives\":/ in elements[e] )
                            {
                            temp = split_string(elements[e], /:/);
			    positives = temp[1];
                            #positives = sub_bytes(temp[1], 2, |temp[2]|);
                            }
                        else if ( /\"total\":/ in elements[e] )
                            {
                            temp = split_string(elements[e], /:/);
                            #total = sub_bytes(temp[2], 2, |temp[2]|);
			    total = temp[1];
                            }
                        else if ( /\"result\":/ in elements[e] )
                            {
                            if ( ! ( / null/ in elements[e] ) )
                                {
                                temp = split_string(elements[e], /\"/);
                                results[|results|] = temp[1];
                                }
                            }
                        }

		  switch response
			{
			case "r 0":
				context = "The requested resource is not among the finished, queued or pending scans";
				subcon = "";
				break;
			case "r 1":
				context =  fmt("%s / %s flagged as positive", positives, total);
				subcon = join_string_vec(results, ",");
				break;
			default:
				context = fmt("Error in communication: response_code %s", response);
				subcon = "";
				break;
			}

                    if ( ! ( context == "" ) )
                        {
                        local id: conn_id;
                        local c: connection;
                        local uid: string;
                        for ( conn in f$conns )
                            id = conn;
                        for ( u in f$info$conn_uids )
                            uid = u;
                        c$id = id;
                        c$uid = uid;
                        NOTICE([$note=VirusTotal::Result, $msg=context, $sub=subcon, $conn=c]);
                        }
                    }
                }
            }
        }
    }
