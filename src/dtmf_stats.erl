%%% @author Luis Urrea <lfurrea@gmail.com>
%%% @copyright (C) 2015, Luis Urrea
%%% @doc
%%%
%%% @end
%%% Created : 21 Dec 2015 by Luis Urrea <lfurrea@gmail.com>

-module(dtmf_stats).
-export([parse/1, parse/2, strip_header/1, poor_mans_fsm/1, rtpevent/2]).

-record(state, {name = finished }).
-record(digit, {marker, pt, seqnum, ts, ssrc, digit, eoe, volume, duration}).

-define(LAYER2_HEADER_SIZE, 16).
-define(LAYER3_HEADER_SIZE, 20).
-define(LAYER4_HEADER_SIZE, 8).

parse(Fname) when is_list(Fname) ->
    case file:read_file(Fname) of
        {ok, Bin} ->            
            {ok, Packets }= parse(strip_header(Bin)),
            State = #state{},
            Pid = spawn(?MODULE, poor_mans_fsm, [State]),
            lists:map(fun (A) -> rtpevent(A, Pid) end, Packets);
        {error, Reason} ->
            {error, Reason}
    end;
parse(Bin) when is_binary(Bin) ->
    parse(Bin, []).

parse(<<_TsSec:32, _TsUsec:32, InclLen:32/unsigned-little-integer, _OrigLen:32/unsigned-little-integer
        , _DestMAC:48, _SourceMAC:48, _Space:16, _Layer3Proto:16, _Layer3Ver:4, _Layer3Len:4, _DSCP:8 
        , _Misc:56, _Layer4Proto:8, _HdrChecksum:16, _SourceIP:32, _DestIP:32, _SourcePort:16, _DestPort:16
        ,_DgramLength:16, _Checksum:16 , Rest/binary>>, Acc) ->
    Len = InclLen - (?LAYER2_HEADER_SIZE+?LAYER3_HEADER_SIZE+?LAYER4_HEADER_SIZE),
    <<Packet:Len/binary, NewRest/binary>> = Rest,
    parse(NewRest, [Packet|Acc]); 
parse(<<>>, Acc) ->
    {ok, lists:reverse(Acc)}.

strip_header(Bin) ->
    <<MagicNumber:32,_Version_Major:16, _Version_Minor:16, Timezone:32, Sigfig:32, Snaplen:32/unsigned-little-integer, Network:32/unsigned-little-integer, Rest/binary>> = Bin,
    lager:info("Magic Number: ~b, TZ: ~b, Sigfig: ~b ,Snap: ~b, Net: ~b~n", [MagicNumber, Timezone, Sigfig, Snaplen, Network]),
    Rest.

rtpevent(<<_VerMisc:8, Marker:1, PT:7, SequenceNumber:16, Timestamp:32, SSRC:32, DTMFDigit:8, EndOfEvent:1, _Reserved:1
    , Volume:6, Duration:16>>, Pid) ->
    Digit = #digit{marker = Marker, pt = PT, seqnum = SequenceNumber, ts = Timestamp
                  , ssrc = SSRC, digit = DTMFDigit, eoe = EndOfEvent, volume = Volume
                   , duration = Duration},
    lager:info("Marker: ~b EOE: ~b", [Digit#digit.marker, Digit#digit.eoe]),
    Pid ! {rtpevent, Digit}.


% Poor man's fsm
poor_mans_fsm(State = #state{}) ->
    receive
        {rtpevent, Digit} when Digit#digit.marker =:= 1, Digit#digit.eoe =:= 0, State#state.name =:= finished  ->
            %This is a new digit coming in
            lager:info("This is a new digit coming in!"),
            NewState = State#state{name=started},
            poor_mans_fsm(NewState);
        {rtpevent, Digit} when Digit#digit.marker =:= 0, Digit#digit.eoe =:= 0, State#state.name =:= finished ->
            %This should not happen
            lager:info("This should never happen!"),
            poor_mans_fsm(State);
        {rtpevent, Digit} when Digit#digit.marker =:= 0, Digit#digit.eoe =:= 1, State#state.name =:= finished ->
            %This is reasurance in case it was missed
            lager:info("Retransmission of End Event"),
            poor_mans_fsm(State);
        {rtpevent, Digit} when Digit#digit.marker =:= 1, Digit#digit.eoe =:= 0, State#state.name =:= started ->
            %This is an inconsistency (may be part of another conversation)
            lager:info("Inconsistency, no support for multiple SSRC's"),
            poor_mans_fsm(State);
        {rtpevent, Digit} when Digit#digit.marker =:= 0, Digit#digit.eoe =:= 0, State#state.name =:= started ->
            %increase duration
            lager:info("Increasing duration for digit!"),
            poor_mans_fsm(State);
        {rtpevent, Digit} when Digit#digit.marker =:= 0, Digit#digit.eoe =:= 1, State#state.name =:= started ->
            %This is the end of the digit
            lager:info("End of digit received, total duration:"),
            NewState = State#state{name=finished},
            poor_mans_fsm(NewState)
    end.


    


    
    
    

