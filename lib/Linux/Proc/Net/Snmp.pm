use strict;
use warnings;
package Linux::Proc::Net::Read;
use Readonly;

Readonly my $PROC_FILENAME => "/proc/net/snmp";

our $VERSION = "0.01";

sub get_alias { shift }

sub read_file {
    open my $FH, "<", $PROC_FILENAME
        or die "Could not open a file[$PROC_FILENAME] for read: $!";
    chomp( my @lines = <$FH> );
    close $FH
        or die "Could not close a file[$PROC_FILENAME]: $!";
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

sub __clone_array { # only 2 depth.
    my $array_ref = shift;
    my @array = @{ $array_ref };
    $_ = [ @{ $_ } ]
        for @array;
    return @array;
}

# sub __clone_hash { # only 2 depth (id -> heading) clone.  i do not want to increase module dependency.
#     my $hash_ref = shift;
#     my %hash = %{ $hash_ref };
#     $hash{ $_ } = { %{ $hash{ $_ } } }
#         for keys %hash;
#     return %hash;
# }

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
            if ( $sub_id && $stats[ $id ] ) {
                my $index = $index{ $id }{ $sub_id };
                undef $stats[ $id_index ][ $index ]; # filt later, just mark now.
            }
            else {
                undef $stats[ $id_index ];
            }
        }
        elsif ( $indicator eq q{+} ) {
            if ( $sub_id ) {
                my $index = $index{ $id }{ $sub_id };
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

=encoding utf-8

=head1 NAME

Linux::Proc::Net::Read reads /proc/net/snmp, and construct perl data

=head1 SYNOPSIS




=head1 EXAMPLE DATA

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
