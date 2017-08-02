#!/usr/bin/perl
# This script will gather the cert expiration and contact information from the policy db,
# and send out the necessary notifications to the relevant groups
# The script will search through each fragment for the different cert formats and use the
# most recently specified contact information for any notifications that need to be sent.

use Net::SMTP;

$curDate = `date +%s`;chomp($curDate);
$curDatePretty = `date`;chomp($curDatePretty);
@adminContacts = ("admins\@admin.com");
$emailResults = "No errors detected when sending notifications";
#@environments = ("dev","qa","prod","ext");
@environments = ("qa");
$pathToData = "/home/user";


# loop through the different environments
# to process the fragments
foreach $env (@environments){
        $emailResults = "No errors detected when sending notifications";
        processEnvironment($env);
}


# expects the environment name
sub processEnvironment{
        $lenvironment = shift;

        # grab the fragment data
        open($fh,"<","$pathToData/$lenvironment/resolution-fragments.csv");
        $buf = "";
        while($row = <$fh>){
                $buf .= $row;
        }
        @lines = split('\[\]\[\]\[\]',$buf);


        # client certs extracted from db
        # needed to match the assertions that use client cert auth
        # with an identity provider
        $clientCertsRaw = `cat $pathToData/$lenvironment/client_cert.csv`;
        @clientCertsSplit = split('\[\]\[\]\[\]',$clientCertsRaw);
        @clientCerts = ();
        foreach $cert (@clientCertsSplit){
                $cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        }

        # search through fragments for relevant keys and data
        $newxml = "";
        foreach $line (@lines){
                ($name,$xml) = split('\|\|\|\|',$line);

                #current contacts will be filled with the most recently found contact information
                #of the current fragment
                @currentContacts = ();
                @certs = ();
                $inSPecificUser=0;

                #split the xml and look for the relevant comment data
                @sxml = split('\n',$xml);
                foreach $line (@sxml){

                        # this is needed to detect certs that are specified
                        # using the identity provider:
                        if($line =~ /\<L7p\:SpecificUser\>/){$inSpecificUser=1;next;}
                        if($line =~ /\<\/L7p\:SpecificUser\>/){$inSpecificUser=0;next;}
                        if($line =~ /\<L7p\:UserName stringValue\=\"(.*)\"\/\>/ && $inSpecificUser){
                                $tmpName = $1;
                                foreach $icert (@clientCertsSplit){
                                        $tmpVal = getRawCertNameAndDate($icert);
                                        $tmpcn = "";
                                        if($tmpVal =~ /.*CN\=(.*)\ Expires.*/){$tmpcn = $1;}
					if($tmpName eq $tmpcn && hasRawCertExpired($icert)){addToCerts(\@certs,$tmpVal);}
                                }
                        }

                        # this will handle contact information
                        # the format for contact information expects:
                        # CertOwners_<email1>;<email2>;<email3> etc.
                        if($line =~ /\<L7p\:Comment stringValue\=\"CertOwners_(.*)\"\/\>/){
                                @scontacts = split(/\;/,$1);
                                foreach $contact (@scontacts){
                                        push(@currentContacts,$contact);
                                }
                                next;
                        }

                        # this will handle certs that use thumbprint authentication and
                        # specify the cert name and expiration in the following comment format:
                        # <certname>_Expires_<expirationdate>
                        # This format is deprecated in favor of the "RawCert" format below
                        if($line =~ /\_Expires\_/){
                                if($line =~ /\<L7p\:Comment stringValue=\"(.*)\"/){
                                        if(hasCommentCertExpired($1)){
                                                addToCerts(\@certs,$1);
                                                next;
                                        }
                                }
                        }

                        # This will handle certs that use thumbprint authentication and
                        # specify the raw cert in the following comment format:
                        # RawCert_<base64cert>
                        if($line =~ /RawCert\_(.*)\"\/\>/){
                                if(hasRawCertExpired($1)){
                                        addToCerts(\@certs,$1);
                                }
                        }
                }

                # if there are certs that have expired or will expire, send to the
                # appropriate contact groups
                if(@certs > 0){
                        # if no contact information was found about these certs
                        # add to the certs that will be sent to the administrators
                        # else, send to appropriate contact group
                        if(@currentContacts == 0){
                                foreach $c (@certs){addToCerts(\@adminCerts,$c);}
                        }
                        else{sendEmail(\@certs,\@currentContacts,"Cert Expiration Notification","The following certs appear to be expiring soon","");}
                }
        }

        sendEmail(\@adminCerts,\@adminContacts,"Cert notification report for $lenvironment","The following certs appear to be expiring soon and no contact information was found for them",$emailResults);
}








# Sends an email to notification group for the expiring certs
# ARG1 should be an array containing the certs and expiration dates
# ARG2 should be an array of the contacts
# ARG3 should be the email subject
# ARG4 should be a header for the body of the email
# ARG5 should be any text notes to add to the email
sub sendEmail{
        $lcerts = shift;
        $lcontacts = shift;
        $lsubject = shift;
        $lheader = shift;
        $lnotes = shift;

        # format some of the data so it can be used in an email
        $scerts = "";
        $scontacts = "";
        print "sending to ";
        foreach $c (@$lcontacts){
                print "$c,";
                $scontacts .= "$c,";
        }
        chop($scontacts);
        print "\n";
        print "Subject: $lsubject\n";

        foreach $c (@$lcerts){
                print "- $c\n";
                $scerts .= "- $c\n";
        }

        print "\n";
        print "Notes:\n";
        print "$lnotes\n\n";

        #return;

        # send the email, record any errors and add to the emailResults to send
        # to the admins
        my $smtp;
        if(!($smtp = Net::SMTP->new("mailserver.com", Port=>25, Timeout => 10, Debug => 1))){
                $emailResults .= "Error when connecting to mail server.\n";
                $emailResults .= "Could not send email to $scontacts for certs:\n$scerts\n";
                debugLog("Error when connecting to mail server\nCould not send email to $scontacts for certs:\n$scerts\n");
                return;
        }
        #die "Could not connect to server!\n" unless $smtp;

        if(!($smtp->hello('mailserver.com'))){
                $emailResults .= "Error when sending hello to mail server.\n";
                $emailResults .= "Could not send email to $scontacts for certs:\n$scerts\n";
                debugLog("Error when sending hello to mail server.\nCould not send email to $scontacts for certs:\n$scerts\n");
                return;
        }
        $smtp->mail( 'user@mailserver.com' );
        if(!($smtp->recipient(@$lcontacts))){
                $emailResults .= "Error when setting recipients.\n";
                $emailResults .= "Could not send email to $scontacts for certs:\n$scerts\n";
                debugLog("Error when setting recipients.\nCould not send email to $scontacts for certs:\n$scerts\n");
                return;
        }
        $smtp->data;

        $toString = "";
        foreach $c (@$lcontacts){
                $c =~ s/\@/\\\@/g;
                $toString .= $c;
        }
        $smtp->datasend("From: user@mailserver.com\r\n");
        $smtp->datasend("To: $toString\r\n");
        $smtp->datasend("Subject: $lsubject\r\n");
        $smtp->datasend("\r\n");

        $smtp->datasend( "$lheader\n\n$scerts\nNotes: $lnotes\n");
        $smtp->dataend;
        $smtp->quit;

        debugLog("Successfully sent email to $scontacts for certs:\n$scerts\n");

}

# Expects a string to add to the debug log
sub debugLog{
        $l = shift;
        open(my $fh, ">>","/home/user/certExpirationNotifications.log");
        print $fh "--- $curDatePretty\n$l\n---\n";
        close($fh);
}

# Expects the format:
# <Certname>_Expires_<date>
# returns 1 if cert will expire in 90 days or has expired
# returns 0 if cert expiration is greater than 90 days away
sub hasCommentCertExpired{
        $comment = shift;

        $certExpiration = "";
        if($comment =~ /Expires\_(.*)/){$certExpiration = $1;}

        $epoch = `date --date="$certExpiration" +%s`;chomp($epoch);
        $diff = $epoch - $curDate;

        if($diff < 7776000 && $diff > 0){
                return 1;
        }
        return 0;
}




# Expects the format:
# RawCert_<base64cert>
# returns 1 if the cert will expire in 90 days or has expired
# returns 0 if the cert expiration is greater than 90 days away
sub hasRawCertExpired{
        $comment = shift;

        $certExpiration = "";
        #clean up and format the base64 encoded cert
        $c = formatRawCert($comment);

        #extract data from the raw cert using openssl
        # store the cert expiration in certExpiration
        @r = `echo "-----BEGIN CERTIFICATE-----\n$c\n-----END CERTIFICATE-----" | openssl x509 -noout -text`;
        $certExpiration = "";
        $certName = "";
        foreach $line (@r){
                if($line =~ /Not After \: (.*)\n/){
                        $certExpiration = $1;
                }
                if($line =~ /Subject\: .*CN\=(.*)/){
                        $certName = $1;
                 }
        }
        chomp($certExpiration);
        $epoch = `date --date="$certExpiration" +%s`;chomp($epoch);
        $diff = $epoch - $curDate;
        if($diff < 7776000 && $diff > 0){
        #if($diff < 100007776000){
                return 1;
        }
        return 0;
}

# gets the base64 encoded cert name and date
# returns a string of the cert name and date
sub getRawCertNameAndDate{
        $comment = shift;

        $certName="";
        $certExpiration="";

        #clean up and format the base64 encoded cert
        $c = formatRawCert($comment);

        #extract data from the raw cert using openssl
        # store the cert expiration in certExpiration
        @r = `echo "-----BEGIN CERTIFICATE-----\n$c\n-----END CERTIFICATE-----" | openssl x509 -noout -text`;
        $certExpiration = "";
        $certName = "";
        foreach $line (@r){
                if($line =~ /Not After \: (.*)\n/){
                        $certExpiration = $1;
                }
                if($line =~ /Subject\:(.*)/){
                #if($line =~ /Subject\:.*CN\=(.*)/){
                        $certName = $1;
                }
        }
        $certName =~ s/^\ +//g;
        return $certName . " Expires " . $certExpiration;

}

# cleans up a base64 encoded cert that is found in the policy to the format
# that openssl expects
# returns the formated output as a string
sub formatRawCert{
        $r = shift;
        $r =~ s/\-+BEGIN CERTIFICATE\-+//g;
        $r =~ s/\-+END CERTIFICATE\-+//g;
        $r =~ s/\ //g;
        $r =~ s/\n//g;
        @groups = ();
        push @groups, substr $r, 0, 64, '' while length $r;
        $r="";
        foreach $w (@groups){
                $r .="$w\n";
        }
        chomp($r);
        return $r;
}

# expects an array of certs and the cert to add
# adds the cert to the array of certs in order
# by date
sub addToCerts{
        $lcerts = shift;
        $lcert = shift;

        # format properly if this is a raw cert
        $lcertFormat = formatRawCert($lcert);
        $lcertName = "";
        if($lcertFormat =~ /^MII/){$lcertName = getRawCertNameAndDate($lcertFormat);}
        else{$lcertName = $lcert;}

        #print "lcert is $lcertName\n";
        # if the array is empty, add the first value
        if(@$lcerts == 0){
                #print "empty array, pushing $lcertName\n";
                push(@$lcerts,$lcertName);
                return;
        }

        # get the epoch time of the cert being added
        $lcertEpochTime = "";
        if($lcertName =~ /\ Expires\ (.*)/){
                $lcertEpochTime = `date --date="$1" +%s`;chomp($lcertEpochTime);
        }
        elsif($lcertName =~ /\Expires_(.*)/){
                $lcertEpochTime = `date --date="$1" +%s`;chomp($lcertEpochTime);
        }

        # insert the new cert before the first cert that has an
        # expiration date greater than the current cert
        $i=0;
        $l=0;
        foreach $c (@$lcerts){
                #print "size is " . @$lcerts . " i is $i c is $c\n";
                if($c =~ /\ Expires\ (.*)/){
                        $l = `date --date="$1" +%s`;chomp($l);
                }
                elsif($c =~ /\Expires_(.*)/){
                        $l = `date --date="$1" +%s`;chomp($l);
                }

                #print "comparing $lcertEpochTime and $l\n";
                #print "certs are $c and $lcertName\n";
                if($l > $lcertEpochTime){splice(@$lcerts,$i,0,$lcertName);last;}
                $i++;

                # if this is the last loop, add the value
                # to the end of the array
                if($i == @$lcerts){push(@$lcerts,$lcertName);last;}
        }
}
