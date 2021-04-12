global orig_hStart_time:table[addr] of time=table();
global orig_h404Resp:table[addr] of count=table();
global orig_hResp:table[addr] of count=table();
global orig_h404URLResp:table[addr] of set[string]=table();

event http_reply(c: connection, version: string, code: count, reason: string)
{
   local time_now:time=network_time();
   if(c$id$orig_h !in orig_hStart_time)
  {
    orig_hStart_time[c$id$orig_h]=time_now;
    orig_h404Resp[c$id$orig_h]=0;
    orig_hResp[c$id$orig_h]=0;
    orig_h404URLResp[c$id$orig_h]=set();
  }
  local duration:interval=time_now-orig_hStart_time[c$id$orig_h];
  if(duration>10mins)
  {
    orig_hStart_time[c$id$orig_h]=time_now;
    if( orig_h404Resp[c$id$orig_h]>2)
    {
      if(orig_h404Resp[c$id$orig_h]/orig_hResp[c$id$orig_h]>0.2)
      {
        if(|orig_h404URLResp[c$id$orig_h]|/orig_h404Resp[c$id$orig_h]>0.5)
        {
          print cat(c$id$orig_h)+" is a scanner with "+cat(orig_h404Resp[c$id$orig_h])+" scan attemps on "+cat(|orig_h404URLResp[c$id$orig_h]|)+" urls";
        }
      }
    }
    orig_h404Resp[c$id$orig_h]=0;
    orig_hResp[c$id$orig_h]=0;
    orig_h404URLResp[c$id$orig_h]=set();
   }

   orig_hResp[c$id$orig_h]=orig_hResp[c$id$orig_h]+1;
   if(code==404)
   {
     orig_h404Resp[c$id$orig_h]=orig_h404Resp[c$id$orig_h]+1;
     if(c$http$uri !in orig_h404URLResp[c$id$orig_h])
     {
       add orig_h404URLResp[c$id$orig_h][c$http$uri];   
     }
   }
}
