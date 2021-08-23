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
unit MainFrame;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ExtCtrls,
  Interfaces, oauth2Client, IdHTTP, IdSSLOpenSSL;

const
  {User for Resource Owner Password Grant}
  UserName = 'atester';
  Password = 'test2021';

type

  { TForm1 }

  TForm1 = class(TForm)
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    httpClient: TIdHTTP;
    SSLHandler: TIdSSLIOHandlerSocketOpenSSL;
    ResourceBtn: TButton;
    CancelBtn: TButton;
    OAuth2Client: TOAuth2Client;
    RadioGroup1: TRadioGroup;
    ScopeSelection: TRadioGroup;
    RefreshBtn: TButton;
    Memo1: TMemo;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure CancelBtnClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure OAuth2ClientAccessToken(Sender: TObject; AccessToken,
      RefreshToken, TokenScope: string; expires_in: integer);
    procedure OAuth2ClientErrorResponse(Sender: TObject; E: Exception);
    procedure RadioGroup1Click(Sender: TObject);
    procedure RefreshBtnClick(Sender: TObject);
    procedure ResourceBtnClick(Sender: TObject);
  private
    FRefreshToken: string;
    FAccessToken: string;
  end;

var
  Form1: TForm1;

implementation

uses URIParser, oauth2tokens;

const ResourceURL: string = 'http://localhost/oauth2/resource.php';

{$R *.lfm}

type

  { TResouceResponse }

  TResouceResponse = class(TOAuth2Response)
  private
    FMessage: string;
    FSuccess: string;
  protected
     procedure ValidateResponse; override;
  public
    constructor Create(responseStr: string);
  published
    property success: string read FSuccess write FSuccess;
    property message: string read FMessage write FMessage;
  end;

{ TResouceResponse }

procedure TResouceResponse.ValidateResponse;
begin
  //nothing to validate
end;

constructor TResouceResponse.Create(responseStr: string);
begin
  inherited Create;
  ParseJsonResponse(responseStr);
end;

{ TForm1 }

procedure TForm1.Button1Click(Sender: TObject);
var AccessToken: string;
    expires_in: integer;
    TokenScope: string;
begin
    try
      OAuth2Client.GrantClientCredentials(ScopeSelection.Items[ScopeSelection.ItemIndex],AccessToken,TokenScope,expires_in);
      Memo1.Lines.Add('Get Client Credentials: Access Token = "' + AccessToken + '"');
      Memo1.Lines.Add('Expires In = ' + IntToStr(expires_in) + ' seconds, Scope = ' + TokenScope);
    except on E: Exception do
      Memo1.Lines.Add('Error: ' + E.message);
    end;
    FAccessToken := AccessToken;
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
    try
      OAuth2Client.GrantAuthorizationCodeAsync(ScopeSelection.Items[ScopeSelection.ItemIndex]);
      Memo1.Lines.Add('Enter credentials in web browser');
    except on E: Exception do
      begin
        Memo1.Lines.Add('Error: ' + E.message);
      end;
    end;
    CancelBtn.Enabled := true;
end;

procedure TForm1.Button3Click(Sender: TObject);
var AccessToken: string;
    RefreshToken: string;
    TokenScope: string;
    expires_in: integer;
begin
    try
      OAuth2Client.GrantUserPasswordCredentials(ScopeSelection.Items[ScopeSelection.ItemIndex],UserName,Password,
             AccessToken,RefreshToken,TokenScope,expires_in);
      Memo1.Lines.Add('Get User Password Credentials: Access Token = "' + AccessToken + '"');
      Memo1.Lines.Add('Refresh Token = "' + RefreshToken + '"');
      Memo1.Lines.Add('Scope = "' + TokenScope + '"');
      Memo1.Lines.Add('Expires In = ' + IntToStr(expires_in) + ' seconds');
      if RefreshToken <> '' then
        FRefreshToken := RefreshToken;
      RefreshBtn.Enabled := RefreshToken <> '';
    except on E: Exception do
      Memo1.Lines.Add('Error: ' + E.message);
    end;
    FAccessToken := AccessToken;
end;

procedure TForm1.Button4Click(Sender: TObject);
begin
  try
    OAuth2Client.ImplicitGrantAsync(ScopeSelection.Items[ScopeSelection.ItemIndex]);
    Memo1.Lines.Add('Enter credentials in web browser');
  except on E: Exception do
    begin
      Memo1.Lines.Add('Error: ' + E.message);
    end;
  end;
  CancelBtn.Enabled := true;
end;

procedure TForm1.CancelBtnClick(Sender: TObject);
begin
  OAuth2Client.CancelGrantRequest;
  CancelBtn.Enabled := false;
end;

procedure TForm1.FormShow(Sender: TObject);
var ENVURI,EndpointURI: TURI;
    AuthServer: string;
begin
  Memo1.Clear;
  AuthServer := GetEnvironmentVariable('AUTHSERVER');
  if AuthServer <> '' then
  begin
    ENVURI := ParseURI(AuthServer);
    EndpointURI := ParseURI(OAuth2Client.AuthEndPoint);
    EndpointURI.Protocol := ENVURI.Protocol;
    EndpointURI.Host := ENVURI.Host;
    OAuth2Client.AuthEndPoint := EncodeURI(EndpointURI);
    EndpointURI := ParseURI(OAuth2Client.TokenEndPoint);
    EndpointURI.Protocol := ENVURI.Protocol;
    EndpointURI.Host := ENVURI.Host;
    OAuth2Client.TokenEndPoint := EncodeURI(EndpointURI);

    EndpointURI := ParseURI(ResourceURL);
    EndpointURI.Protocol := ENVURI.Protocol;
    EndpointURI.Host := ENVURI.Host;
    ResourceURL := EncodeURI(EndpointURI);
  end;
  Memo1.Lines.Add('Auth End Point = ' + OAuth2Client.AuthEndPoint);
  Memo1.Lines.Add('Token End Point = ' + OAuth2Client.TokenEndPoint);
  Memo1.Lines.Add('Resource URL = ' + ResourceURL);
end;

procedure TForm1.OAuth2ClientAccessToken(Sender: TObject; AccessToken,
  RefreshToken, TokenScope: string; expires_in: integer);
begin
  Memo1.Lines.Add('Get Authorization Code: Access Token = "' + AccessToken+ '"');
  Memo1.Lines.Add('Refresh Token = "' + RefreshToken + '"');
  if RefreshToken <> '' then
    FRefreshToken := RefreshToken;
  if TokenScope <> '' then
  Memo1.Lines.Add('Scope Returned = ' + TokenScope);
  Memo1.Lines.Add('Expires In = ' + IntToStr(expires_in) + ' seconds');
  RefreshBtn.Enabled := true;
  CancelBtn.Enabled := false;
  FAccessToken := AccessToken;
end;

procedure TForm1.OAuth2ClientErrorResponse(Sender: TObject; E: Exception);
begin
  Memo1.Lines.Add('Error Response: ' + E.message);
  CancelBtn.Enabled := false;
end;

procedure TForm1.RadioGroup1Click(Sender: TObject);
begin
  case RadioGroup1.ItemIndex of
  0:
    OAuth2Client.ClientAuthType := caBasic;
  1:
    OAuth2Client.ClientAuthType := caInline;
  end;
end;

procedure TForm1.RefreshBtnClick(Sender: TObject);
var AccessToken: string;
    TokenScope: string;
    NewRefreshToken: string;
    expires_in: integer;
begin
    try
      OAuth2Client.RefreshAccessToken('',FRefreshToken,AccessToken,TokenScope,NewRefreshToken,expires_in);
      Memo1.Lines.Add('Refresh Token: Access Token = "' + AccessToken + '" ' +
                       'Replacement Refresh Token = "' + NewRefreshToken + '" Expires In =' +
                       IntToStr(expires_in) + ' seconds, Scope = ' + TokenScope);
      if NewRefreshToken <> '' then
        FRefreshToken := NewRefreshToken;
    except on E: Exception do
      Memo1.Lines.Add('Error: ' + E.message);
    end;
    FAccessToken := AccessToken;
end;

procedure TForm1.ResourceBtnClick(Sender: TObject);
var Request: TOAuth2URLEncodedData;
    Response: TStringStream;
    ResouceResponse: TResouceResponse;
begin
  if FAccessToken = '' then
    ShowMessage('You must get an Access Token First!')
  else
  begin
    if ParseURI(ResourceURL).Protocol = 'https' then
      httpClient.IOHandler := SSlHandler;
    httpClient.ConnectTimeout := 5000;
    httpClient.ReadTimeout := 5000;
    Request := TOAuth2URLEncodedData.Create;
    Response := TStringStream.Create('');
    try
      Request.AddParam('access_token',FAccessToken);
      httpClient.Post(ResourceURL,Request,Response);
      Memo1.Lines.Add('Response  = ' + IntToStr(httpClient.ResponseCode) + ' ' + httpClient.ResponseText);
      Memo1.Lines.Add('Response Body: ' + Response.DataString);
      ResouceResponse := TResouceResponse.Create(Response.DataString);
      try
        Memo1.Lines.Add('Parsed Response Body');
        Memo1.Lines.Add('Success = ' + ResouceResponse.success);
        Memo1.Lines.Add('Message = ' + ResouceResponse.message);
      finally
        ResouceResponse.Free;
      end;
    finally
      Request.Free;
      Response.Free;
    end;
  end;
end;


end.

