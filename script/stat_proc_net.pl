#!/usr/bin/perl -s
use utf8;
use strict;
use warnings;
use Data::Dumper;

our $interval  ||= 2;
our $iteration ||= 10;
our $in        ||= "/proc/net/netstat";
our $verbose;

$Data::Dumper::Terse    = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

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

package main;
my $reader = Linux::Proc::Net::Read->get_alias;

my @field_specs = $in eq "/proc/net/netstat"
? qw(
    -IpExt
    -TcpExt
    +TcpExt.DelayedACKLocked
    +TcpExt.DelayedACKLost
    +TcpExt.TCPFastRetrans
    +TcpExt.TCPForwardRetrans
    +TcpExt.TCPFullUndo
    +TcpExt.TCPLossFailures
    +TcpExt.TCPLossUndo
    +TcpExt.TCPLostRetransmit
    +TcpExt.TCPPartialUndo
    +TcpExt.TCPSackFailures
    +TcpExt.TCPSackRecoveryFail
    +TcpExt.TCPSlowStartRetrans
)
: qw(
    -Ip
    +Ip.InDiscards
    +Ip.ForwDatagrams
    +Ip.InDelivers
    +Ip.OutRequests
    +Ip.ReasmTimeout
    +Ip.ReasmReqds
    +Ip.ReasmOKs
    +Ip.ReasmFails

    -Icmp
    +Icmp.InMsgs
    +Icmp.InErrors
    +Icmp.InDestUnreachs
    +Icmp.InEchos
    +Icmp.InEchoReps
    +Icmp.OutMsgs
    +Icmp.OutDestUnreachs
    +Icmp.OutEchos
    +Icmp.OutEchoReps

    -Tcp.RtoAlgorithm
    -Tcp.RtoMin
    -Tcp.RtoMax
    -Tcp.MaxConn

    -Udp
    +Udp.InDatagrams
    +Udp.OutDatagrams
    +Udp.SndbufErrors

    -UdpLite
);

$|++;

my $count;

while ( $count++ < $iteration ) {
    my $measured_at = time;
    my( $stats_ref, $index_ref ) = $reader->parse_lines( $reader->read_file( $in ) );

    if ( $verbose ) {
        my %stat = $reader->construct_stat( $stats_ref, $index_ref );
        print $measured_at, "\t", Data::Dumper->new( [ \%stat ] )->Indent( 0 )->Dump, "\n";
    }
    else {
        my @fields = $reader->extract_fields( \@field_specs, $stats_ref, $index_ref );
        print $measured_at, "\t", join( "\t", @fields ), "\n";
    }

    sleep $interval;
}

exit;

