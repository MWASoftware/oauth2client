{
    This file is part of the MWA Software OAuth2 Client.

    The MWA Software OAuth2 Client is free software: you can redistribute it
    and/or modify it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    The MWA Software OAuth2 Client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with the MWA Software OAuth2 Client.  If not, see <https://www.gnu.org/licenses/>.
}
program oauth2test;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils, CustApp,
  { you can add units after this }
  oauth2Client, oauth2tokens,URIParser;

const
  {User for Resource Owner Password Grant}
  UserName = 'atester';
  Password = 'test2021';

type

  { OAuth2ConsoleTest }

  OAuth2ConsoleTest = class(TCustomApplication)
  private
    FOAuth2Client: TOAuth2Client;
    FRefreshToken: string;
    procedure UpdateEndPoints;
    procedure TestExtensionGrant(Scope: string);
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure DoTests(scope: string);
    procedure WriteHelp; virtual;
  end;

{ OAuth2ConsoleTest }

procedure OAuth2ConsoleTest.DoTests(scope: string);
var AccessToken: AnsiString;
    RefreshToken: AnsiString;
    expires_in: integer;
    TokenScope: AnsiString;
    NewRefreshToken: string;
begin
  writeln('Get Client Credentials');
  try
    FOAuth2Client.GrantClientCredentials(scope,AccessToken,TokenScope,expires_in);
    writeln('Get Client Credentials: Access Token = "' + AccessToken + '"');
    writeln('Expires In = ' + IntToStr(expires_in) + ' seconds, Scope = ' + TokenScope);
  except on E: Exception do
    writeln('Error: ' + E.message);
  end;

  writeln('Test Extension Grant using Get Client Credentials');
  TestExtensionGrant(scope);

  writeln('Get User Password Credentials');
  try
    FOAuth2Client.GrantUserPasswordCredentials(scope,UserName,Password,
           AccessToken,RefreshToken,TokenScope,expires_in);
    writeln('Get User Password Credentials: Access Token = "' + AccessToken + '"');
    writeln('Refresh Token = ' + RefreshToken + '"');
    writeln('Expires In = ' + IntToStr(expires_in) + ' seconds, Scope = ' + TokenScope);
    if RefreshToken <> '' then
      FRefreshToken := RefreshToken;
  except on E: Exception do
    writeln('Error: ' + E.message);
  end;

  if FRefreshToken <> '' then
  begin
    writeln('Refresh Token');
    try
      FOAuth2Client.RefreshAccessToken('',FRefreshToken,AccessToken,TokenScope,NewRefreshToken,expires_in);
      writeln('Refresh Token: Access Token = "' + AccessToken + '" ' +
                       'Replacement Refresh Token = "' + NewRefreshToken + '" Expires In =' +
                       IntToStr(expires_in) + ' seconds, Scope = ' + TokenScope);
      if NewRefreshToken <> '' then
        FRefreshToken := NewRefreshToken;
    except on E: Exception do
      writeln('Error: ' + E.message);
    end;
  end
  else
    writeln('No Refresh Token');

  writeln('Get Authorization Grant');
  try
    FOAuth2Client.GrantAuthorizationCode(scope,AccessToken,RefreshToken,TokenScope,expires_in);
    writeln('Get Authorization Grant Credentials: Access Token = "' + AccessToken + '"');
    writeln('Refresh Token = ' + RefreshToken + '"');
    writeln('Expires In = ' + IntToStr(expires_in) + ' seconds, Scope = ' + TokenScope);
    if RefreshToken <> '' then
      FRefreshToken := RefreshToken;
  except on E: Exception do
    writeln('Error: ' + E.message);
  end;

  writeln('Get Implicit Grant');
  try
    FOAuth2Client.ImplicitGrant(scope,AccessToken,TokenScope,expires_in);
    writeln('Get Implicit Grant Credentials: Access Token = "' + AccessToken + '"');
    writeln('Expires In = ' + IntToStr(expires_in) + ' seconds, Scope = ' + TokenScope);
    if RefreshToken <> '' then
      FRefreshToken := RefreshToken;
  except on E: Exception do
    writeln('Error: ' + E.message);
  end;
end;

procedure OAuth2ConsoleTest.UpdateEndPoints;
var ENVURI,EndpointURI: TURI;
    AuthServer: string;
begin
  AuthServer := GetEnvironmentVariable('AUTHSERVER');
  if AuthServer <> '' then
  begin
    ENVURI := ParseURI(AuthServer);
    EndpointURI := ParseURI(FOAuth2Client.AuthEndPoint);
    EndpointURI.Protocol := ENVURI.Protocol;
    EndpointURI.Host := ENVURI.Host;
    FOAuth2Client.AuthEndPoint := EncodeURI(EndpointURI);
    EndpointURI := ParseURI(FOAuth2Client.TokenEndPoint);
    EndpointURI.Protocol := ENVURI.Protocol;
    EndpointURI.Host := ENVURI.Host;
    FOAuth2Client.TokenEndPoint := EncodeURI(EndpointURI);
  end;
  writeln('Auth End Point = ' + FOAuth2Client.AuthEndPoint);
  writeln('Token End Point = ' + FOAuth2Client.TokenEndPoint);
end;

procedure OAuth2ConsoleTest.TestExtensionGrant(Scope: string);
var Response: TBearerTokenResponse;
    LocalParams: TStringList;
begin
  {Test emulates a Client credentials Grant using an ExtensionGrant}
  LocalParams := TStringList.Create;
  Response := TBearerTokenResponse.Create;
  try
    LocalParams.Values['scope'] := Scope;
    try
      FOAuth2Client.ExtensionGrant('client_credentials',LocalParams,Response);
      writeln('Get Client Credentials using Extension Grant: Access Token = "' + Response.access_token + '"');
      writeln('Expires In = ' + IntToStr(Response.expires_in) + ' seconds, Scope = ' + Response.scope);
    except on E: Exception do
      writeln('Error: ' + E.message);
    end;
  finally
    Response.Free;
    LocalParams.Free;
  end;
end;

procedure OAuth2ConsoleTest.DoRun;
var
  ErrorMsg: String;
begin
  // quick check parameters
  ErrorMsg := CheckOptions('h', 'help');
  if ErrorMsg <> '' then begin
    ShowException(Exception.Create(ErrorMsg));
    Terminate;
    Exit;
  end;

  // parse parameters
  if HasOption('h', 'help') then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

  { add your program here }

  // stop program loop
  Terminate;
end;

constructor OAuth2ConsoleTest.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException := True;
  FOAuth2Client := TOAuth2Client.Create(self);
  FOAuth2Client.AuthEndPoint := 'http://localhost/oauth2/authorise.php';
  FOAuth2Client.TokenEndPoint := 'http://localhost/oauth2/token.php';
  FOAuth2Client.ClientID := 'OAuth2Tester';
  FOAuth2Client.ClientSecret := 'masterkey';
  UpdateEndPoints;
end;

destructor OAuth2ConsoleTest.Destroy;
begin
  inherited Destroy;
end;

procedure OAuth2ConsoleTest.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ', ExeName, ' -h');
end;

var
  Application: OAuth2ConsoleTest;
begin
  Application := OAuth2ConsoleTest.Create(nil);
  Application.Title:='OAuth2 Testing';
  Application.Run;
  Application.DoTests('testing');
  Application.DoTests('bad');
  Application.Free;
end.

