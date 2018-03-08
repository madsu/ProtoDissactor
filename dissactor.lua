do
    local data_dis = Dissector.get("data")
    local xx_proto = Proto("XX", "XX Protolcol")
    function xx_proto_dissector(tvb, pinfo, treeitem)
        local offset = 0
        local current_len = tvb:range(offset,4):le_uint()
        if(current_len <= 4) then
            data_dis:call(tvb, pinfo, treeitem)
            return
        end
        
        if(offset + current_len > tvb:len()) then
            return
        end
        
        offset = offset+4
        local current_moduleid = tvb:range(offset, 2):le_uint()
        offset = offset+2
        local current_protocolid = tvb:range(offset, 2):le_uint()
        offset = offset+2
        local dissector_func = moudles[current_moduleid][current_protocolid]
        if dissector_func ~= nil then
            dissector_func:call(tvb:range(offset-4):tvb(), pinfo, treeitem)
        else
            data_dis:call(tvb, pinfo, treeitem)
        end
    end

    function xx_proto.dissector(tvb, pinfo, treeitem)
        if tvb:len() < 4 then
           data_dis:call(tvb, pinfo, treeitem)
           return
        end
        
        local offset = pinfo.desegment_offset or 0
        while (offset < tvb:len())
        do
            if(tvb:len() - offset < 4) then
                pinfo.desegment_len = offset + 4 - tvb:len()
                pinfo.desegment_offset = offset
                return
            end
            
            local current_len = tvb:range(offset,4):le_uint()
            local nxtpdu = offset + current_len
            
            if(nxtpdu > tvb:len()) then
                pinfo.desegment_len = nxtpdu - tvb:len()
                pinfo.desegment_offset = offset
                return
            end
            
            xx_proto_dissector(tvb:range(offset, current_len), pinfo, treeitem)
            offset = nxtpdu
        end
    end

    local tcp_port_table = DissectorTable.get("tcp.port")
    tcp_port_table:add(1234, xx_proto)
end
