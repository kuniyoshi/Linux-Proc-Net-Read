use strict;
use warnings;
package Linux::Proc::Net::Read;

# ABSTRACT: reads /proc/net/{netstat,snmp}, and construct perl data structrue

our $VERSION = "0.01";

sub get_alias { shift }

sub read_file {
    shift
        if $_[0] eq __PACKAGE__;

    my $filename = shift;

    open my $FH, "<", $filename
        or die "Could not open a file[$filename] for read: $!";
    chomp( my @lines = <$FH> );
    close $FH
        or die "Could not close a file[$filename]: $!";

    return @lines;
}

sub parse_lines {
    shift
        if $_[0] eq __PACKAGE__;

    my @lines = @_;
    my @stats;
    my %index;

    for my $line ( @lines ) {
        my( $id, $headings_or_numbers ) = split m{:\s}, $line, 2;
        my @headings_or_numbers = split m{\s}, $headings_or_numbers;
        my $is_numbers = !grep { m{[^-\d]} } @headings_or_numbers;

        if ( !$is_numbers ) {
            my @headings = @headings_or_numbers;

            $index{ $id }{self} = @stats;
            $index{ $id }{ $headings[ $_ ] } = $_
                for 0 .. $#headings;
        }
        else {
            my @numbers = @headings_or_numbers;
            push @stats, \@numbers;
        }
    }

    return \@stats, \%index;
}

sub construct_stat {
    shift
        if $_[0] eq __PACKAGE__;

    my( $stats_ref, $index_ref ) = @_;
    my %stat;

    for my $id ( keys %{ $index_ref } ) {
        for my $sub_id ( keys %{ $index_ref->{ $id } } ) {
            next
                if $sub_id eq "self";

            my $number = $stats_ref->[ $index_ref->{ $id }{self} ][ $index_ref->{ $id }{ $sub_id } ];
            $stat{ $id }{ $sub_id } = $number;
        }
    }

    return %stat;
}

sub get_fields {
    shift
        if $_[0] eq __PACKAGE__;

    my $index_ref = shift;
    my @fields;

    for my $id ( sort { $index_ref->{ $a }{self} <=> $index_ref->{ $b }{self} } keys %{ $index_ref } ) {
        for my $sub_id ( sort { $index_ref->{ $id }{ $a } <=> $index_ref->{ $id }{ $b } } keys %{ $index_ref->{ $id } } ) {
            next
                if $sub_id eq "self";
            push @fields, join q{.}, $id, $sub_id;
        }
    }

    return @fields;
}

sub __clone_array { # only 2 depth.  i do not want to increase dependency modules.
    my $array_ref = shift;
    my @array = @{ $array_ref };
    $_ = [ @{ $_ } ]
        for @array;
    return @array;
}

sub filt_stat {
    shift
        if $_[0] eq __PACKAGE__;

    my @filter_specs = @{ shift( ) };
    my @stats        = __clone_array( shift );
    my %index        = %{ shift( ) };
    my @stats_backup = __clone_array( \@stats );

    for my $spec ( @filter_specs ) {
        my( $indicator, $id_may_with_sub_id ) = split m{}, $spec, 2;
        my( $id, $sub_id ) = split m{[.]}, $id_may_with_sub_id;
        my $id_index = $index{ $id }{self};

        if ( $indicator eq q{-} ) {
            if ( $sub_id && $stats[ $id_index ] ) {
                my $index = $index{ $id }{ $sub_id };
                warn "No [$sub_id] found"
                    if !defined $index;
                undef $stats[ $id_index ][ $index ]; # filt later, just mark now.
            }
            else {
                undef $stats[ $id_index ];
            }
        }
        elsif ( $indicator eq q{+} ) {
            if ( $sub_id ) {
                my $index = $index{ $id }{ $sub_id };
                warn "No [$sub_id] found"
                    if !defined $index;
                $stats[ $id_index ][ $index ] = $stats_backup[ $id_index ][ $index ];
            }
            else {
                $stats[ $id_index ] = [ @{ $stats_backup[ $id_index ] } ];
            }
        }
    }

    @stats = grep { defined } @stats;
    $_ = [ grep { defined } @{ $_ } ]
        for @stats;

    return @stats;
}

sub __flatten {
    my $array_ref = shift;
    my @array = map { @{ $_ } } @{ $array_ref };
    return @array;
}

sub extract_fields {
    shift
        if $_[0] eq __PACKAGE__;

    my @specs     = @{ shift( ) };
    my $stats_ref = shift;
    my $index_ref = shift;
    my @stats     = filt_stat( \@specs, $stats_ref, $index_ref );

    return __flatten( \@stats );
}

1;

__END__
=pod

=encoding utf8

=head1 NAME

Linux::Proc::Net::Read reads /proc/net/{netstat,snmp}, and construct perl data structrue

=head1 SYNOPSIS

  my $reader = Linux::Proc::Net::Read->get_alias;
  my( $stats_ref, $index_ref ) = $reader->parse_lines( $reader->read_file( "/proc/net/snmp" ) );

  my @fields = $reader->extract_fields(
      [ qw( -Ip -Icmp -IcmpMsg -Tcp -Udp -UdpLite +Tcp.InSegs +Tcp.OutSegs ) ],
      $stats_ref,
      $index_ref,
  );

  print join( "\t", @fields ), "\n";

=head1 DESCRIPTION

Reads `/proc/net/snmp`, or `/proc/net/netstat`.

These files are formatted like below:

  {Id.1}: {SubId.1} {SubId.2} {SubId.3} ...
  {Id.1}: {Counter for SubId.1} {Counter for SubId.2} {Counter for SubId.3} ...
  {Id.2}: {SubId.1} {SubId.2} {SubId.3} ...
  {Id.2}: {Counter for SubId.1} {Counter for SubId.2} {Counter for SubId.3} ...
  ...

The format is not easy to extract.  To extract the counter, this module parses
these lines, nad construct perl data.  After the data is perl, extraction is
easy.

The order of ID is important than code readability.  Thus this module generates
Array rather than Hash.  When the data is Array, it requires index data.

=head1 EXAMPLE DATA

  /proc/net/snmp

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

  /proc/net/netstat

  TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSPassive PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPPrequeued TCPDirectCopyFromBacklog TCPDirectCopyFromPrequeue TCPPrequeueDropped TCPHPHits TCPHPHitsToUser TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPFACKReorder TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPForwardRetrans TCPSlowStartRetrans TCPTimeouts TCPLossProbes TCPLossProbeRecovery TCPRenoRecoveryFail TCPSackRecoveryFail TCPSchedulerFailed TCPRcvCollapsed TCPDSACKOldSent TCPDSACKOfoSent TCPDSACKRecv TCPDSACKOfoRecv TCPAbortOnData TCPAbortOnClose TCPAbortOnMemory TCPAbortOnTimeout TCPAbortOnLinger TCPAbortFailed TCPMemoryPressures TCPSACKDiscard TCPDSACKIgnoredOld TCPDSACKIgnoredNoUndo TCPSpuriousRTOs TCPMD5NotFound TCPMD5Unexpected TCPSackShifted TCPSackMerged TCPSackShiftFallback TCPBacklogDrop TCPMinTTLDrop TCPDeferAcceptDrop IPReversePathFilter TCPTimeWaitOverflow TCPReqQFullDoCookies TCPReqQFullDrop TCPRetransFail TCPRcvCoalesce TCPOFOQueue TCPOFODrop TCPOFOMerge TCPChallengeACK TCPSYNChallenge TCPFastOpenActive TCPFastOpenPassive TCPFastOpenPassiveFail TCPFastOpenListenOverflow TCPFastOpenCookieReqd TCPSpuriousRtxHostQueues BusyPollRxPackets
  TcpExt: 0 0 7 10 1726327 0 0 0 0 0 126935 0 0 0 0 765 1213615 3202 9401 0 0 268959 119172 134863980 66 74775403 98789 8399260 567526 0 52 0 0 0 0 0 0 0 4 21757 0 0 10 116 282 9 0 104931 19813 19009 0 0 0 8079643 8026 6 3017 0 143 101 0 333 0 0 0 0 0 2632 19 0 0 667 427 325 1180 0 1373 6 0 0 0 0 96725165 232199 0 7 1579 1572 0 0 0 0 0 3 0
  IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors
  IpExt: 8 0 1373448 67 2933402 0 172057411322 5677157400 205756672 12178 381874535 0 22559
