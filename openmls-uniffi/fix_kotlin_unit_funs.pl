#!/usr/bin/perl
use strict;
use warnings;

local $/;
undef $/;
my $content = <STDIN>;

my @lines = split(/\n/, $content, -1);
my @result;
my $i = 0;
my $n = scalar(@lines);

while ($i < $n) {
    my $line = $lines[$i];

    # Detect: a fun declaration line ending with ) (no return type = Unit),
    # followed by a line that is purely whitespace + "=" + optional whitespace
    if ($i + 1 < $n 
        && $line =~ /\)\s*$/
        && $line !~ /:\s*\S/
        && $lines[$i+1] =~ /^\s+=\s*$/) {

        # Rewrite function signature: append " {"
        push @result, $line . " {";
        $i += 2;  # skip the bare "=" line

        # Collect body until braces are balanced (depth returns to 0)
        my $depth = 0;
        my $started = 0;
        while ($i < $n) {
            my $bline = $lines[$i];
            my $opens  = () = $bline =~ /\{/g;
            my $closes = () = $bline =~ /\}/g;
            $depth += $opens - $closes;
            push @result, $bline;
            $i++;
            $started = 1 if $opens > 0 || $closes > 0 || $bline =~ /\S/;
            last if $started && $depth <= 0;
        }

        # Close the function block
        push @result, "    }";

    } else {
        push @result, $line;
        $i++;
    }
}

print join("\n", @result);
