NAME
====

Linux::Proc::Net::Read reads /proc/net/{netstat,snmp}, and construct perl data structrue

SYNOPSIS
========

``` perl
  my $reader = Linux::Proc::Net::Read->get_alias;
  my( $stats_ref, $index_ref ) = $reader->parse_lines( $reader->read_file( "/proc/net/snmp" ) );
  
  my @fields = $reader->extract_fields(
      [ qw( -Ip -Icmp -IcmpMsg -Tcp -Udp -UdpLite +Tcp.InSegs +Tcp.OutSegs ) ],
      $stats_ref,
      $index_ref,
  );
  
  print join( "\t", @fields ), "\n";
```

DESCRIPTION
===========

Reads `/proc/net/snmp`, or `/proc/net/netstat`.

These files are formatted like below:

```
  {Id.1}: {SubId.1} {SubId.2} {SubId.3} ...
  {Id.1}: {Counter for SubId.1} {Counter for SubId.2} {Counter for SubId.3} ...
  {Id.2}: {SubId.1} {SubId.2} {SubId.3} ...
  {Id.2}: {Counter for SubId.1} {Counter for SubId.2} {Counter for SubId.3} ...
  ...
```

The format is not easy to extract. To extract the counter, this module
parses these lines, nad construct perl data. After the data is perl,
extraction is easy.

The order of ID is important than code readability. Thus this module
generates Array rather than Hash. When the data is Array, it requires
index data.

EXAMPLE DATA
============

/proc/net/snmp
--------------
    
```
  Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
  Ip: 1 64 143326089 22090 0 36 0 0 137489637 85398346 28 0 2 1272 618 2 0 0 0
  Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
  Icmp: 943998 4 0 580913 0 0 0 0 362735 350 0 0 0 0 946528 0 583418 0 0 0 0 375 362735 0 0 0 0
  IcmpMsg: InType0 InType3 InType8 OutType0 OutType3 OutType8
  IcmpMsg: 350 580913 362735 362735 583418 375
  Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
  Tcp: 1 200 120000 -1 4199726 29153 4668 245 4 134558068 81174107 109993 1548 25965 0
  Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors
  Udp: 2006714 211 211 3277843 0 0 0
  UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors
  UdpLite: 0 0 0 0 0 0 0
```
    
/proc/net/netstat
-----------------
    
```
  TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSPassive PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPPrequeued TCPDirectCopyFromBacklog TCPDirectCopyFromPrequeue TCPPrequeueDropped TCPHPHits TCPHPHitsToUser TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPFACKReorder TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPForwardRetrans TCPSlowStartRetrans TCPTimeouts TCPLossProbes TCPLossProbeRecovery TCPRenoRecoveryFail TCPSackRecoveryFail TCPSchedulerFailed TCPRcvCollapsed TCPDSACKOldSent TCPDSACKOfoSent TCPDSACKRecv TCPDSACKOfoRecv TCPAbortOnData TCPAbortOnClose TCPAbortOnMemory TCPAbortOnTimeout TCPAbortOnLinger TCPAbortFailed TCPMemoryPressures TCPSACKDiscard TCPDSACKIgnoredOld TCPDSACKIgnoredNoUndo TCPSpuriousRTOs TCPMD5NotFound TCPMD5Unexpected TCPSackShifted TCPSackMerged TCPSackShiftFallback TCPBacklogDrop TCPMinTTLDrop TCPDeferAcceptDrop IPReversePathFilter TCPTimeWaitOverflow TCPReqQFullDoCookies TCPReqQFullDrop TCPRetransFail TCPRcvCoalesce TCPOFOQueue TCPOFODrop TCPOFOMerge TCPChallengeACK TCPSYNChallenge TCPFastOpenActive TCPFastOpenPassive TCPFastOpenPassiveFail TCPFastOpenListenOverflow TCPFastOpenCookieReqd TCPSpuriousRtxHostQueues BusyPollRxPackets
  TcpExt: 0 0 7 10 1726327 0 0 0 0 0 126935 0 0 0 0 765 1213615 3202 9401 0 0 268959 119172 134863980 66 74775403 98789 8399260 567526 0 52 0 0 0 0 0 0 0 4 21757 0 0 10 116 282 9 0 104931 19813 19009 0 0 0 8079643 8026 6 3017 0 143 101 0 333 0 0 0 0 0 2632 19 0 0 667 427 325 1180 0 1373 6 0 0 0 0 96725165 232199 0 7 1579 1572 0 0 0 0 0 3 0
  IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors
  IpExt: 8 0 1373448 67 2933402 0 172057411322 5677157400 205756672 12178 381874535 0 22559
```
