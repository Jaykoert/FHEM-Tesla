=head1
        49_TeslaConnection.pm

# $Id: $

        Version 1.0

=head1 SYNOPSIS
        Tesla Motors Modul for FHEM
        contributed by Stefan Willmeroth 07/2017
        
        Get started by defining a TeslaConnection and search your cars: 
        define teslaconn TeslaConnection
        set teslaconn scanCars

=head1 DESCRIPTION
        49_TeslaConnection keeps the logon token needed by devices defined by
        49_TeslaCar

=head1 AUTHOR - Stefan Willmeroth
        swi@willmeroth.com (forum.fhem.de)
	Forked by Timo Dostal and Jaykoert all credits goes to Stefan Willmeroth & mrmops
=cut

package main;

use strict;
use warnings;
use HttpUtils;
use JSON;
use URI::Escape;
use Switch;
use Data::Dumper; #debugging


##############################################
sub TeslaConnection_Initialize($)
{
  my ($hash) = @_;

  $hash->{SetFn}        = "TeslaConnection_Set";
  $hash->{DefFn}        = "TeslaConnection_Define";
  $hash->{GetFn}        = "TeslaConnection_Get";
  $hash->{AttrList}  	= "AccessToken";

}

###################################
sub TeslaConnection_Set($@)
{
  my ($hash, @a) = @_;

  return "no set value specified" if(int(@a) < 2);
  #return "LoginNecessary" if($a[1] eq "?" && !defined($gotToken));
  return "scanCars login logout" if($a[1] eq "?");
  if ($a[1] eq "login") {
    TeslaConnection_Login($hash, $hash->{NAME});
  }
  if ($a[1] eq "scanCars") {
    TeslaConnection_AutocreateDevices($hash);
  }
  if ($a[1] eq "logout") {
    TeslaConnection_Logout($hash, $hash->{NAME});
  }
}

sub TeslaConnection_Login {
  my ($hash, $name) = @_;

  my $accessToken = AttrVal($name, "AccessToken", "");

  Log3 $name, 4, "Login " . $accessToken;
  if ($accessToken eq "") {
    $hash->{STATE} = "No AccessToken attribute found.";
  } else {
    setKeyValue($name."_accessToken",$attr{$name}{AccessToken});
    $hash->{STATE} = "Connected";
  }

  readingsBeginUpdate($hash);
  readingsBulkUpdate($hash, "state", $hash->{STATE});
  readingsEndUpdate($hash, 1);
}

sub TeslaConnection_Logout {
  my ($hash, $name) = @_;

  setKeyValue($name."_accessToken",undef);
  setKeyValue($name."_refreshToken",undef);
  undef $hash->{expires_at};
  $hash->{STATE} = "Login necessary";
  readingsBeginUpdate($hash);
  readingsBulkUpdate($hash, "state", $hash->{STATE});
  readingsEndUpdate($hash, 1);
}

#####################################
sub TeslaConnection_Define($$)
{
  my ($hash, $def) = @_;
  my @a = split("[ \t][ \t]*", $def);
  my $name   = $a[0];

  my $u = "wrong syntax: define <conn-name> TeslaConnection";

  $hash->{api_uri} = "https://owner-api.teslamotors.com";
  $hash->{client_id} = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384";
  $hash->{client_secret} = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3";
  $hash->{STATE} = "Login necessary";

  # start with a delayed refresh
  setKeyValue($hash->{NAME}."_accessToken",undef);
  InternalTimer(gettimeofday()+10, "TeslaConnection_RefreshToken", $hash, 0);
  InternalTimer(gettimeofday()+10, "TeslaConnection_TryLogin", $hash, 0);

  return;
}

sub TeslaConnection_TryLogin($) {
  my ($hash) = @_;
  my $name = $hash->{NAME};

  my $accessToken = AttrVal($name, "AccessToken", "");

  Log3 $name, 4, "Need to login " . $accessToken;

  if ($accessToken) {
    TeslaConnection_Login($hash, $name);
  }
}





#####################################
sub TeslaConnection_RefreshToken($)
{
  my ($hash) = @_;
  my $name = $hash->{NAME};

  my $conn = $hash->{teslaconn};
  if (!defined $conn) {
    $conn = $hash;
  }
  else {
    $conn = $defs{$conn};
  }


  my ($gkerror, $refreshToken) = getKeyValue($conn->{NAME} . "_refreshToken");
  Log3 $name, 5 , "$name refreshToken params: " . Dumper($refreshToken) . "Error: " .Dumper($gkerror);
  if (!defined $refreshToken) {
    Log3 $name, 4, "$name: no token to be refreshed";
    return undef;
  }

  if (defined($conn->{expires_at})) {
    my ($seconds) = gettimeofday();
    if ($seconds < $conn->{expires_at} - 300) {
      Log3 $name, 4, "$name: no token refresh needed";
      return undef
    }
  }

  my ($gterror, $gotToken) = getKeyValue($conn->{NAME} . "_accessToken");
  Log3 $name, 5 , "$name accessToken params: " . Dumper($gotToken) . "Error: " .Dumper($gterror);
  $hash->{gotToken} = $gotToken;

  my $param = {
      url        => "$conn->{api_uri}/oauth/token",
      timeout    => 10,
      noshutdown => 1,
      httpversion => "1.1",
      hash      => $hash,
      callback   => \&TeslaConnection_RefreshToken_Callback,
      data       => {
          grant_type    => 'refresh_token',
          client_id     => $conn->{client_id},
          client_secret => $conn->{client_secret},
          refresh_token => $refreshToken
      }
  };

  HttpUtils_NonblockingGet($param);
}

sub TeslaConnection_RefreshToken_Callback {
  my ($param, $err, $data) = @_;
  my $hash = $param->{hash};
  my $name = $hash->{NAME};
  my $conn = $hash->{teslaconn};

  if(defined $err) {
    Log3 $name, 2, "$name: http request failed: $err";
  } elsif( $data ) {
    Log3 $name, 4, "$name: RefreshTokenResponse $data";

    $data =~ s/\n//g;
    if( $data !~ m/^{.*}$/m ) {

      Log3 $name, 2, "$name: invalid json detected: >>$data<<";

    } else {
      my $json = eval {decode_json($data)};
      if($@){
        Log3 $name, 2, "$name JSON error while reading refreshed token";
      } else {

        if( $json->{error} ) {
          $hash->{lastError} = $json->{error};
        }
  
        setKeyValue($conn->{NAME}."_accessToken",  $json->{access_token});
        setKeyValue($conn->{NAME}."_refreshToken", $json->{refresh_token});
  
        if( $json->{access_token} ) {
          $conn->{STATE} = "Connected";
          $conn->{expires_at} = gettimeofday();
          $conn->{expires_at} += $json->{expires_in};
          undef $conn->{refreshFailCount};
          readingsBeginUpdate($conn);
          readingsBulkUpdate($conn, "tokenExpiry", scalar localtime $conn->{expires_at});
          readingsBulkUpdate($conn, "state", $conn->{STATE});
          readingsEndUpdate($conn, 1);
          RemoveInternalTimer($conn);
          InternalTimer(gettimeofday()+$json->{expires_in}*3/4,
            "TeslaConnection_RefreshToken", $conn, 0);
          if (!$hash->{gotToken}) {
            foreach my $key ( keys %defs ) {
              if ($defs{$key}->{TYPE} eq "TeslaCar") {
                fhem "set $key init";
              }
            }
          }
          return undef;
        }
      }
      }
    }

  
  $conn->{STATE} = "Refresh Error" ;

  if (defined $conn->{refreshFailCount}) {
    $conn->{refreshFailCount} += 1;
  } else {
    $conn->{refreshFailCount} = 1;
  }

  if ($conn->{refreshFailCount}==10) {
    Log3 $conn->{NAME}, 2, "$conn->{NAME}: Refreshing token failed too many times, stopping";
    $conn->{STATE} = "Login necessary";
    setKeyValue($hash->{NAME}."_refreshToken", undef);
  } else {
    RemoveInternalTimer($conn);
    InternalTimer(gettimeofday()+60, "TeslaConnection_RefreshToken", $conn, 0);
  }

  readingsBeginUpdate($hash);
  readingsBulkUpdate($hash, "state", $hash->{STATE});
  readingsEndUpdate($hash, 1);
  return undef;
}

#####################################
sub TeslaConnection_AutocreateDevices
{
  my ($hash) = @_;

  #### Read list of vehicles
  my $URL = "/api/1/vehicles";

  $hash->{dataCallback} = sub {
    my $carJson = shift;

    Log3 $hash->{NAME}, 5, "car scan response $carJson";

    if (!defined $carJson) {
      return "Failed to connect to TeslaConnection API, see log for details";
    }

    my $cars = decode_json ($carJson);

    for (my $i = 0; 1; $i++) {
      my $car = $cars->{response}[$i];
      if (!defined $car) { last };
      if (!defined $defs{$car->{vin}}) {
        fhem ("define $car->{vin} TeslaCar $hash->{NAME} $car->{vin}");
      }
    }

    return undef;
  };

  Log3 $hash->{NAME}, 3, "start car scan";

  TeslaConnection_request($hash,$URL);

}

#####################################
sub TeslaConnection_Undef($$)
{
   my ( $hash, $arg ) = @_;

   RemoveInternalTimer($hash);
   Log3 $hash->{NAME}, 3, "--- removed ---";
   return undef;
}

#####################################
sub TeslaConnection_Get($@)
{
  my ($hash, @args) = @_;

  return 'TeslaConnection_Get needs two arguments' if (@args != 2);

  my $get = $args[1];
  my $val = $hash->{Invalid};

  return "TeslaConnection_Get: no such reading: $get";

}

#####################################
sub TeslaConnection_request
{
  my ($hash, $URL) = @_;
  my $name = $hash->{NAME};

  my $api_uri = (defined $hash->{teslaconn}) ? $defs{$hash->{teslaconn}}->{api_uri} : $hash->{api_uri};

  $URL = $api_uri . $URL;

  Log3 $name, 4, "$name request: $URL";
  Log3 $name, 5, "$name callback function: $hash->{dataCallback}";

  TeslaConnection_RefreshToken($hash);

  my $conn = $hash->{teslaconn};
  if (!defined $conn) {
    $conn = $name;
  }
  my ($gkerror, $token) = getKeyValue($conn."_accessToken");

  if (!$token) {
    Log3 $name, 1, "$name token is undef";
    return undef;
  }

  my $param = {
    url        => $URL,
    hash       => $hash,
    timeout    => 3,
    noshutdown => 1,
      httpversion => "1.1",
    header     => { "Accept" => "application/json", "Authorization" => "Bearer $token" },
      callback  => \&TeslaConnection_request_callback,
  };

  Log3 $name, 5 , "$name request params: " . Dumper($param) . " Error: ". Dumper($gkerror) . " Token: " . Dumper($token);
  HttpUtils_NonblockingGet($param);
}

sub TeslaConnection_request_callback {
  my ($param, $err, $data) = @_;
  my $name = $param->{hash}->{NAME};

  if ($err) {
    Log3 $name, 2, "$name can't $param->{URL} -- " . $err;
    return undef;
  }

  Log3 $name, 5 , "$name response: " . $data . " and params: " . Dumper($param) . " callback function: " . $param->{hash}->{dataCallback};
  ;

  if ($data && $param->{hash}->{dataCallback}) {
    $param->{hash}->{dataCallback}->($data);
  }
}

#####################################
sub TeslaConnection_postdatarequest
{
  my ($hash, $URL, $put_data) = @_;
  my $name = $hash->{NAME};

  my $api_uri = (defined $hash->{teslaconn}) ? $defs{$hash->{teslaconn}}->{api_uri} : $hash->{api_uri};

  $URL = $api_uri . $URL;

  Log3 $name, 4, "$name POST request: $URL with data: $put_data";

  TeslaConnection_RefreshToken($hash);

  my $conn = $hash->{teslaconn};
  if (!defined $conn) {
    $conn = $name;
  }
  my ($gkerror, $token) = getKeyValue($conn."_accessToken");

  my $param = {
    url        => $URL,
    method     => "POST",
    hash       => $hash,
    timeout    => 3,
    noshutdown => 1,
    header     => { "Accept" => "application/json",
                    "Authorization" => "Bearer $token",
                    "Content-Type" => "application/json"
                  },
      httpversion => "1.1",
    data       => $put_data,
    callback  => \&TeslaConnection_request_callback,
  };

  HttpUtils_NonblockingGet($param);
}



#####################################
sub TeslaConnection_delrequest
{
  my ($hash, $URL) = @_;
  my $name = $hash->{NAME};

  my $api_uri = (defined $hash->{teslaconn}) ? $defs{$hash->{teslaconn}}->{api_uri} : $hash->{api_uri};

  $URL = $api_uri . $URL;

  Log3 $name, 4, "TeslaConnection DELETE request: $URL";

  TeslaConnection_RefreshToken($hash);

  my $conn = $hash->{teslaconn};
  if (!defined $conn) {
    $conn = $name;
  }
  my ($gkerror, $token) = getKeyValue($conn."_accessToken");

  my $param = {
    url        => $URL,
    method     => "DELETE",
    hash       => $hash,
    timeout    => 3,
    noshutdown => 1,
      httpversion => "1.1",
    header     => { "Accept" => "application/json", "Authorization" => "Bearer $token" },
   callback  => \&TeslaConnection_request_callback,
  };

  HttpUtils_NonblockingGet($param);
}

#####################################
sub TeslaConnection_postrequest
{
  my ($hash, $URL) = @_;
  my $name = $hash->{NAME};

  my $api_uri = (defined $hash->{teslaconn}) ? $defs{$hash->{teslaconn}}->{api_uri} : $hash->{api_uri};

  $URL = $api_uri . $URL;

  Log3 $name, 4, "TeslaConnection POST request: $URL";

  TeslaConnection_RefreshToken($hash);

  my $conn = $hash->{teslaconn};
  if (!defined $conn) {
    $conn = $name;
  }
  my ($gkerror, $token) = getKeyValue($conn."_accessToken");

  my $param = {
    url        => $URL,
    method     => "POST",
    hash       => $hash,
    timeout    => 3,
    noshutdown => 1,
      httpversion => "1.1",
    header     => { "Accept" => "application/json", "Authorization" => "Bearer $token" },
    callback  => \&TeslaConnection_request_callback,
  };

  HttpUtils_NonblockingGet($param);
}

1;

=pod
=begin html

<a name="TeslaConnection"></a>
<h3>TeslaConnection</h3>
<ul>
  <a name="TeslaConnection_define"></a>
  <h4>Define</h4>
  <ul>
    <code>define &lt;name&gt; TeslaConnection</code>
    <br/>
    <br/>
    Defines a connection and login to Tesla.<br>
    <br/>
    The following steps are needed:<br/>
    <ul>
      <li>Define the FHEM TeslaConnection device<br/>
      <code>define teslaconn TeslaConnection</code><br/></li>
      <li>Add attribute AccessToken with a token created in a third party app, e.g. "Tesla Token".</li>
      <li>Execute set login</li>
      <li>Execute the set scanDevices action to create TeslaCar devices for your vehicles.</li>
    </ul>
  </ul>
  <br/>
  <a name="TeslaConnection_set"></a>
  <b>Set</b>
  <ul>
    <li>scanCars<br/>
      Start a vehicle scan of the Tesla account. The registered cars will then be created as devices automatically
      in FHEM. The device scan can be started several times and will not duplicate cars.
      </li>
    <li>login<br/>
      Reads the access token and switches state to connected.
    </li>
    <li>logout<br/>
      Delete the access token and refresh tokens.
    </li>
  </ul>
  <br/>

</ul>

=end html
=cut
