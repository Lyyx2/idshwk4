@load base/frameworks/sumstats
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="httpResp", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="404httpResp", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="404URIhttpResp", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="httpStats",
                      $epoch=10mins,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local res1 = result["httpResp"];
                        local res2 = result["404httpResp"];
                        local res3 = result["404URIhttpResp"];
                        if(res2$sum>2){
                        if(res2$sum/res1$sum>0.2){
                        if(res3$unique/res2$sum>0.5){
                        print fmt("%s is a scanner with %g scan attemps on %d urls", 
                        			key$host, res2$sum, res3$unique);
                        }}}
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    SumStats::observe("httpResp", [$host=c$id$orig_h],[$num=1]);
    if ( code==404 )
       { SumStats::observe("404httpResp", [$host=c$id$orig_h], [$num=1]);
       SumStats::observe("404URIhttpResp", [$host=c$id$orig_h], [$str=c$http$uri]);}
    }
