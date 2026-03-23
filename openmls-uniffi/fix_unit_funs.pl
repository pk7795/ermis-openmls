#!/usr/bin/perl
use strict;
use warnings;

my $file = $ARGV[0] or die "Usage: $0 <file.kt>\n";

open(my $fh, '<', $file) or die "Cannot open $file: $!";
my @lines = <$fh>;
close($fh);

# Remove trailing newlines for uniform processing
chomp @_ for @lines;
chomp $_ for @lines;

my @out;
my $n = scalar(@lines);
my $i = 0;
my $changes = 0;

while ($i < $n) {
    my $line = $lines[$i];

    # Look-ahead: if next line is purely whitespace + "=" + optional spaces
    # (the bare "=" expression-body marker for Unit functions)
    if ($i + 1 < $n && $lines[$i + 1] =~ /^\s+=\s*$/) {
        # This line should be a fun signature ending with ")"
        # (Unit return, no ":" return type after the closing paren)
        if ($line =~ /\)\s*$/ && $line !~ /\):\s*\S/) {
            $changes++;
            # Append " {" to close the signature and open block body
            push @out, $line . " {";

            # Skip the bare "=" line
            $i += 2;

            # Collect body: balanced braces starting from next non-empty line
            my $depth = 0;
            my $body_started = 0;

            while ($i < $n) {
                my $bline = $lines[$i];
                my $opens  = () = $bline =~ /\{/g;
                my $closes = () = $bline =~ /\}/g;

                push @out, $bline;
                $i++;

                if ($opens > 0 || $bline =~ /\S/) {
                    $body_started = 1;
                }

                $depth += $opens - $closes;

                if ($body_started && $depth <= 0) {
                    last;
                }
            }

            # Add closing brace for the function block
            push @out, "    }";
            next;
        }
    }

    push @out, $line;
    $i++;
}

# Write back
open(my $out_fh, '>', $file) or die "Cannot write $file: $!";
print $out_fh join("\n", @out) . "\n";
close($out_fh);

print "Done. Fixed $changes Unit function(s).\n";
