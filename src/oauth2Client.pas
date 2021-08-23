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
unit oauth2Client;

{ See RFC 6749  The OAuth 2.0 Authorization Framework

  This class implements the:
    * Authorization Code Grant
    * Client Credentials Grant
    * Refreshing an Access Token
    * Resource Owner Password Credentials Grant
    * Implicit Grant
    * Extension Grant

  It uses the System Browser for supporting an Authorization Code Grant and
  an Implicit Grant, and an embedded HTTPS server running as a separate thread.
}

{$mode ObjFPC}{$H+}

interface

uses Classes, Sysutils, IdHTTPServer, IdGlobal, IdContext,IdHeaderList,
  IdCustomHTTPServer, SyncObjs, oauth2tokens, oauth2errors;


type
  TOAuth2BrowserResponseType = (rtSuccess,rtError,rtIgnored,rtRedirect);
  TOAuth2OnGetBrowserResponseBody = procedure(Sender: TObject; ResponseType: TOAuth2BrowserResponseType; Contents: TMemoryStream) of object;
  TOAuth2OnErrorResponse = procedure(Sender: TObject; E: Exception) of object;
  TOAuth2OnAccessTokenExt = procedure(Sender: TObject; Response: TOAuth2TokenResponse) of object;
  TOAuth2OnAccessToken = procedure(Sender: TObject; AccessToken, RefreshToken, TokenScope: string;
    expires_in: integer) of object;

  TOAuth2AuthGrantState = (agIdle,agWaitAuthCode,agWaitRedirect,agWaitAccessCode,agWaitSessionEnd);

  TOAuth2ClientAuthType = (caBasic,caInline);


  { TOAuth2Client }

  TOAuth2Client = class(TComponent)
  private type

    { TResponseHandler }

    TResponseHandler = class
    protected
      FResponse: TOAuth2TokenResponse;
    public
      procedure AccessTokenReceived; virtual; abstract;
      procedure ErrorResponseReceived(E: Exception); virtual; abstract;
      procedure GrantCompleted; virtual; abstract;
      property Response: TOAuth2TokenResponse read FResponse;
    end;

    { TAsyncResponseHandler }

    TAsyncResponseHandler = class(TResponseHandler)
    private
      FOwner: TOAuth2Client;
      FThreadException: Exception;
      procedure DoOnAccessToken;
      procedure DoOnErrorResponse;
    public
      constructor Create(aOwner: TOAuth2Client; ResponseClass: TOAuth2TokenResponseClass);
      destructor Destroy; override;
      procedure AccessTokenReceived; override;
      procedure ErrorResponseReceived(E: Exception); override;
      procedure GrantCompleted; override;
    end;

    { TSyncResponseHandler }

    TSyncResponseHandler = class(TResponseHandler)
    private
      FOwner: TOAuth2Client;
      FHasException: boolean;
      FErrorData: TOAuth2ErrorData;
      FUserEventObject: TEventObject;
    public
      constructor Create(aOwner: TOAuth2Client; aResponse: TOAuth2TokenResponse);
      destructor Destroy; override;
      procedure AccessTokenReceived; override;
      procedure ErrorResponseReceived(E: Exception); override;
      procedure GrantCompleted; override;
      function WaitFor(timeout: cardinal): TWaitResult;
    end;

    { TServerStopThread }

    TServerStopThread = class(TThread)
    private
      FOwner: TOAuth2Client;
    protected
      procedure Execute; override;
    public
      constructor Create(Owner: TOAuth2Client);
    end;

  private
    FAuthEndPoint: string;
    FClientAuthType: TOAuth2ClientAuthType;
    FClientID: string;
    FClientSecret: string;
    FOnAccessToken: TOAuth2OnAccessToken;
    FOnAccessTokenExt: TOAuth2OnAccessTokenExt;
    FOnErrorResponse: TOAuth2OnErrorResponse;
    FOnGetBrowserResponseBody: TOAuth2OnGetBrowserResponseBody;
    FRedirectURI: string;
    FTokenEndPoint: string;
    FServer: TIdHTTPServer;
    FState: string;
    FAuthGrantState: TOAuth2AuthGrantState;
    FSettingPort: boolean;
    FResponseHandler: TResponseHandler;
    procedure CheckMainThread;
    function GetPortNo: TIdPort;
    procedure SetPortNo(AValue: TIdPort);
    procedure HandleCommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure HandleDisconnect(AContext: TIdContext);
    procedure InternalGrantAuthorizationCode(Scope: string);
    procedure InternalImplicitGrant(Scope: string);
    procedure GetAccessTokenFromAuthCode(AuthCode: string; Response: TOAuth2TokenResponse);
    function Post(URL: string; Params: TStrings; Response: TOAuth2Response): integer;
    procedure ResetServer;
    procedure setRedirectURI(AValue: string);
  protected
    function BuildImplicitGrantRedirectPage: string; virtual;
  public
    constructor Create(aComponent: TComponent); override;
    destructor Destroy; override;
    procedure GrantClientCredentials(Scope: string;
      var AccessToken: string; var TokenScope: string; var expires_in: integer); overload;
    procedure GrantClientCredentials(Scope: string; Response: TOAuth2TokenResponse); overload;
    procedure GrantUserPasswordCredentials(Scope: string;
      UserName, Password: string; var AccessToken: string; var RefreshToken: string;
      var TokenScope: string; var expires_in: integer); overload;
     procedure GrantUserPasswordCredentials(Scope: string;
      UserName, Password: string;
      Response: TOAuth2TokenResponse); overload;
    procedure GrantAuthorizationCodeAsync(Scope: string; ResponseClass: TOAuth2TokenResponseClass); overload;
    procedure GrantAuthorizationCodeAsync(Scope: string); overload;
    procedure GrantAuthorizationCode(Scope: string; var AccessToken,
      RefreshToken: string; var TokenScope: string; var expires_in: integer; timeout: cardinal=INFINITE); overload;
    procedure GrantAuthorizationCode(Scope: string; Response: TOAuth2TokenResponse; timeout: cardinal=INFINITE); overload;
    procedure ImplicitGrantAsync(Scope: string; ResponseClass: TOAuth2TokenResponseClass); overload;
    procedure ImplicitGrantAsync(Scope: string); overload;
    procedure ImplicitGrant(Scope: string;
      var AccessToken: string; var TokenScope: string; var expires_in: integer; timeout: cardinal=INFINITE); overload;
    procedure ImplicitGrant(Scope: string;  Response: TOAuth2TokenResponse; timeout: cardinal=INFINITE); overload;
    procedure CancelGrantRequest;
    procedure RefreshAccessToken(Scope, RefreshToken: string; var AccessToken: string;
      var TokenScope: string; var NewRefreshToken: string; var expires_in: integer); overload;
    procedure RefreshAccessToken(Scope, RefreshToken: string; Response: TOAuth2TokenResponse); overload;
    procedure ExtensionGrant(GrantType: string; aParams: TStrings;
      Response: TOAuth2TokenResponse);
  published
    property ClientID: string read FClientID write FClientID;
    property ClientSecret: string read FClientSecret write FClientSecret;
    property AuthEndPoint: string read FAuthEndPoint write FAuthEndPoint;
    property TokenEndPoint: string read FTokenEndPoint write FTokenEndPoint;
    property ClientAuthType: TOAuth2ClientAuthType read FClientAuthType write FClientAuthType; {Default to caInline}
    property RedirectURI: string read FRedirectURI write setRedirectURI;
    property PortNo: TIdPort read GetPortNo write SetPortNo; {Defaults to 8080}
    property OnAccessTokenExt: TOAuth2OnAccessTokenExt read FOnAccessTokenExt write FOnAccessTokenExt;
    property OnAccessToken: TOAuth2OnAccessToken read FOnAccessToken write FOnAccessToken;
    property OnErrorResponse: TOAuth2OnErrorResponse read FOnErrorResponse write FOnErrorResponse;
    property OnGetBrowserResponseBody: TOAuth2OnGetBrowserResponseBody read FOnGetBrowserResponseBody write FOnGetBrowserResponseBody;
  end;

  { TOAuth2TextBuffer }

  TOAuth2TextBuffer = class(TMemoryStream)
  private
    function GetDataString: AnsiString;
  public
    property DataString: AnsiString read GetDataString;
  end;

  { TOAuth2URLEncodedData }

  TOAuth2URLEncodedData = class(TOAuth2TextBuffer)
  public
    procedure AddParam(Name, Value: string);
    procedure AddParams(Params: TStrings);
  end;


procedure Register;

implementation

uses IdHTTP, IdURI, IdSSL,IdSSLOpenSSL, IdLogEvent, IdGlobalProtocols,
  IdIntercept,  LCLIntf, LResources, URIParser;

const
  {Response Content Type}
  rcAccept = 'application/vnd.hmrc.1.0+json';

const
  RedirectResponse = 'window.location.href=window.location.origin+''?''+window.location.hash.substring(1);';

resourcestring
  {Default responses to Get Authorization Code/Implicit Grant dialog}
  SOAuth2AccessAuthorized = 'Access Authorized';
  SOAuth2AccessFailed = 'Access Authorization Request Failed';
  SOAuth2RequestIgnored = 'Authorization Code Request Ignored';
  SNoJavascriptSupport =  'Implicit Authorization Failed. Please enable Javascript.';

{ TOAuth2TextBuffer }

function TOAuth2TextBuffer.GetDataString: AnsiString;
begin
  SetLength(Result,Size);
  Position := 0;
  Read(Result[1],Size);
  SetCodePage(RawByteString(Result), DefaultSystemCodePage, False);
end;

{ TOAuth2Client.TServerStopThread }

procedure TOAuth2Client.TServerStopThread.Execute;
begin
  FOwner.ResetServer;
end;

constructor TOAuth2Client.TServerStopThread.Create(Owner: TOAuth2Client);
begin
  inherited Create(false);
  FOwner := Owner;
  FreeOnTerminate := true;
end;

{ TOAuth2Client.TAsyncResponseHandler }

procedure TOAuth2Client.TAsyncResponseHandler.DoOnAccessToken;
begin
  with FOwner do
  begin
    if assigned(FOnAccessTokenExt) then
      OnAccessTokenExt(FOwner,Response)
    else
    if assigned(OnAccessToken) then
    begin
      if Response is TOAuth2BearerTokenResponse then
      with Response as TOAuth2BearerTokenResponse do
        OnAccessToken(FOwner,access_token,refresh_token,scope,expires_in)
      else
      if assigned(FOnErrorResponse) then
      try
       OAuth2Error(erBadAccessTokenType,['bearer',Response.token_type]);
      except on E: Exception do
        OnErrorResponse(self,E);
      end;
    end;
  end;
end;

procedure TOAuth2Client.TAsyncResponseHandler.DoOnErrorResponse;
begin
  if assigned(FOwner.FOnErrorResponse) then
    FOwner.FOnErrorResponse(FOwner,FThreadException);
end;

constructor TOAuth2Client.TAsyncResponseHandler.Create(aOwner: TOAuth2Client;
  ResponseClass: TOAuth2TokenResponseClass);
begin
  inherited Create;
  FOwner := aOwner;
  FResponse := ResponseClass.Create;
end;

destructor TOAuth2Client.TAsyncResponseHandler.Destroy;
begin
  if FResponse <> nil then FResponse.Free;
  inherited Destroy;
end;

procedure TOAuth2Client.TAsyncResponseHandler.AccessTokenReceived;
begin
  TThread.Synchronize(nil,@DoOnAccessToken);
end;

procedure TOAuth2Client.TAsyncResponseHandler.ErrorResponseReceived(
  E: Exception);
begin
  FThreadException := E;
  try
    TThread.Synchronize(nil,@DoOnErrorResponse);
  finally
    FThreadException := nil;
  end;
end;

procedure TOAuth2Client.TAsyncResponseHandler.GrantCompleted;
begin
  TServerStopThread.Create(FOwner);  {Deactivate Server from separate thread}
  FreeAndNil(FOwner.FResponseHandler); {we're no longer needed}
end;


{ TOAuth2Client.TSyncResponseHandler }

constructor TOAuth2Client.TSyncResponseHandler.Create(aOwner: TOAuth2Client;
  aResponse: TOAuth2TokenResponse);
begin
  inherited Create;
  FOwner := aOwner;
  FResponse := aResponse;
  FUserEventObject := TEventObject.Create(nil,false,false,'WaitForAccessCode');
end;

destructor TOAuth2Client.TSyncResponseHandler.Destroy;
begin
  if FUserEventObject <> nil then FUserEventObject.Free;
  inherited Destroy;
end;

procedure TOAuth2Client.TSyncResponseHandler.AccessTokenReceived;
begin
  //Do Nothing
end;

procedure TOAuth2Client.TSyncResponseHandler.ErrorResponseReceived(
  E: Exception);
begin
  FHasException := true;
  if E is EOAuth2Exception then
    (E as EOAuth2Exception).GetErrorData(FErrorData)
  else
    FErrorData.ErrorMessage := E.Message;
  FUserEventObject.SetEvent;
end;

procedure TOAuth2Client.TSyncResponseHandler.GrantCompleted;
begin
  FUserEventObject.SetEvent;
end;

function TOAuth2Client.TSyncResponseHandler.WaitFor(timeout: cardinal): TWaitResult;
begin
  Result := FUserEventObject.WaitFor(timeout);
  Sleep(100); {Give chance for server to fully complete}
  FOwner.ResetServer;
  if FHasException then
  begin
    if FErrorData.StatusCode = 0 then
      raise Exception.Create(FErrorData.ErrorMessage)
    else
      raise EOAuth2Exception.Create(FErrorData);
  end;
end;


{ TOAuth2URLEncodedData }

procedure TOAuth2URLEncodedData.AddParam(Name, Value: string);
var s: string;
begin
  s := Name+'='+TIdURI.ParamsEncode(Value);
  if Size <> 0 then
    s := '&' + s;
  WriteBuffer(s[1],Length(s));
end;

procedure TOAuth2URLEncodedData.AddParams(Params: TStrings);
var i: integer;
begin
  for i := 0 to Params.Count - 1 do
    AddParam(Params.Names[i],Params.ValueFromIndex[i]);
end;

{ TOAuth2Client.TBearerTokenResponse }

{ TOAuth2Client }

procedure TOAuth2Client.CheckMainThread;
begin
  if GetCurrentThreadID <> MainThreadID then
    OAuth2Error(erNotMainThread);
end;

function TOAuth2Client.GetPortNo: TIdPort;
begin
  Result := FServer.DefaultPort;
end;

procedure TOAuth2Client.SetPortNo(AValue: TIdPort);
var URI: TURI;
begin
  FServer.DefaultPort := AValue;
  if FSettingPort then Exit;
  URI := ParseURI(RedirectURI);
  URI.Port := AValue;
  FRedirectURI := EncodeURI(URI);
end;

procedure TOAuth2Client.HandleCommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);

var ResponseType: TOAuth2BrowserResponseType;

procedure ValidateResponse;
begin
  with ARequestInfo do
  begin
    {check state}
    if Params.Values['state'] <> FState then
      OAuth2Error(erUnexpectedState,[FState, Params.Values['state']]);
    FState := '';
    {check for errors}
    if Params.Values['error'] <> '' then
      raise EOAuth2Exception.Create(Params);
  end;
end;

procedure ProcessAuthCode;
var AuthCode: string;
begin
  with ARequestInfo do
  begin
    {extract auth code}
    AuthCode := Params.Values['code'];
    if AuthCode = '' then
      OAuth2Error(erMissingAuthCode);
    FAuthGrantState := agWaitAccessCode;
    {Get access Code}
    GetAccessTokenFromAuthCode(AuthCode,FResponseHandler.Response);
    FResponseHandler.AccessTokenReceived;
    FAuthGrantState := agWaitSessionEnd;
  end;
end;

procedure ProcessAccessCode;
begin
  with ARequestInfo do
  begin
    FResponseHandler.Response.ProcessParams(Params);
    FResponseHandler.AccessTokenReceived;
    FAuthGrantState := agWaitSessionEnd;
  end;
end;

var s: string;
    M: TMemoryStream;

begin
//  writeln('Response: ',ARequestInfo.RawHeaders.Text);
  ResponseType := rtSuccess;
  try
    case FAuthGrantState of
    agWaitAuthCode:
      begin
        ValidateResponse;
        ProcessAuthCode;
      end;

    agWaitAccessCode:
      begin
        if ARequestInfo.Params.IndexOfName('error') <> -1 then
          raise EOAuth2Exception.Create(ARequestInfo.Params);
        ResponseType := rtRedirect;
        FAuthGrantState := agWaitRedirect;
      end;

    agWaitRedirect:
      begin
        if ARequestInfo.Params.Count = 0 then
          {assume browser refresh on javascript enable}
           ResponseType := rtRedirect
        else
        begin
          ValidateResponse;
          ProcessAccessCode;
        end;
      end;
    else
      ResponseType := rtIgnored;
    end;
  except on E: Exception do
     begin
       FResponseHandler.ErrorResponseReceived(E);
       FAuthGrantState := agWaitSessionEnd;
       ResponseType := rtError;
     end;
  end;
  AResponseInfo.ContentType := 'text/html';
  AResponseInfo.ContentEncoding := 'UTF-8';
  AResponseInfo.CharSet := 'UTF-8';
  AResponseInfo.CloseConnection := true;
  M := TMemoryStream.Create;
  if assigned(FOnGetBrowserResponseBody) then
    FOnGetBrowserResponseBody(self,ResponseType,M);
  AResponseInfo.ContentStream := M;
  if AResponseInfo.ContentStream.Size = 0 then
  begin
    case ResponseType of
    rtSuccess:
      s := SOAuth2AccessAuthorized;
    rtError:
      s := SOAuth2AccessFailed;
    rtIgnored:
      s := SOAuth2RequestIgnored;
    rtRedirect:
      s := BuildImplicitGrantRedirectPage;
    end;
    AResponseInfo.ContentStream.WriteBuffer(s[1],length(s));
  end;
  AResponseInfo.ContentStream.Position := 0;
end;

procedure TOAuth2Client.HandleDisconnect(AContext: TIdContext);
begin
  if FAuthGrantState = agWaitSessionEnd then
    FResponseHandler.GrantCompleted;
end;

procedure TOAuth2Client.GetAccessTokenFromAuthCode(AuthCode: string;
  Response: TOAuth2TokenResponse);
var Params: TStringList;
begin
  {RFC 6749 Access Token Request}
  Params := TStringList.Create;
  try
    Params.Values['grant_type'] := 'authorization_code';
    Params.Values['code'] := AuthCode;
    Params.Values['redirect_uri'] := RedirectURI;
    Post(TokenEndPoint,Params,Response);
  finally
    Params.free;
  end;
end;

function TOAuth2Client.Post(URL: string; Params: TStrings;
  Response: TOAuth2Response): integer;
var httpClient: TIdHttp;
    SSlHandler: TIdSSLIOHandlerSocketOpenSSL;
    RequestParams: TOAuth2URLEncodedData;
    ResponseStream: TOAuth2TextBuffer;
begin
  SSlHandler := nil;
  RequestParams := TOAuth2URLEncodedData.Create;
  httpClient := TIdHTTP.Create(nil);
  try
    httpClient.HTTPOptions := httpClient.HTTPOptions + [hoNoProtocolErrorException,
                                                        hoKeepOrigProtocol,
                                                        hoWantProtocolErrorContent];
    httpClient.ProtocolVersion := pv1_1;
    httpClient.Request.CustomHeaders.Clear;
    httpClient.Request.Accept := rcAccept;
    case ClientAuthType of
    caInline:
      begin
        httpClient.Request.BasicAuthentication := false;
        RequestParams.AddParam('client_id',ClientID);
        RequestParams.AddParam('client_secret',ClientSecret);
      end;

    caBasic:
      begin
        httpClient.Request.BasicAuthentication:= true;
        httpClient.Request.UserName := ClientID;
        httpClient.Request.Password := ClientSecret;
      end;
    end;
    RequestParams.AddParams(Params);
    httpClient.Request.UserAgent :=' Mozilla/5.0 (compatible; Indy Library)';
    httpClient.Request.ContentType := 'application/x-www-form-urlencoded';
    if ParseURI(URL).Protocol = 'https' then
    begin
      SSlHandler := TIdSSLIOHandlerSocketOpenSSL.Create(httpClient);
      SSlHandler.SSLOptions.Method := sslvTLSv1_2;
      SSlHandler.SSLOptions.Mode:= sslmClient;
      httpClient.IOHandler := SSlHandler;
    end;
    httpClient.ConnectTimeout := 5000;
    httpClient.ReadTimeout := 5000;
    ResponseStream := TOAuth2TextBuffer.Create;
    try
      httpClient.Post(URL,RequestParams,ResponseStream);
      Result := httpClient.ResponseCode;
      if Result = 200 then
        Response.ParseJsonResponse(ResponseStream.DataString)
      else
        raise EOAuth2Exception.Create(Result,httpClient.ResponseText,ResponseStream.DataString);
    finally
      ResponseStream.Free;
    end;
  finally
    httpClient.Free;
    if RequestParams <> nil then RequestParams.Free;
  end;
end;

procedure TOAuth2Client.ResetServer;
begin
  FServer.Active := false;
  FAuthGrantState := agIdle;
end;

procedure TOAuth2Client.setRedirectURI(AValue: string);
var URI: TURI;
begin
  if FRedirectURI = AValue then Exit;
  URI := ParseURI(AValue,'http',PortNo);
  URI.Params := '';
  URI.Bookmark := '';
  FRedirectURI := EncodeURI(URI);
  FSettingPort := true;
  try
    PortNo := URI.Port;
  finally
    FSettingPort := false;
  end;
end;

function TOAuth2Client.BuildImplicitGrantRedirectPage: string;
begin
  Result := '<html><body>'+
            '<noscript>' + SNoJavascriptSupport + '</noscript>'+
            '<script>' + RedirectResponse + '</script>' +
            '</body></html>';
end;

constructor TOAuth2Client.Create(aComponent: TComponent);
begin
  inherited Create(aComponent);
  FServer := TIdHTTPServer.Create(self);
  FServer.OnCommandGet := @HandleCommandGet;
  FServer.OnDisconnect := @HandleDisconnect;
  FServer.MaxConnections := 1;
  FAuthGrantState := agIdle;
  FClientAuthType := caInline;
  RedirectURI := 'http://localhost:8080';
end;

destructor TOAuth2Client.Destroy;
begin
  if FServer <> nil then
    FServer.Free;
  if FResponseHandler <> nil then FResponseHandler.Free;
  inherited Destroy;
end;

procedure TOAuth2Client.GrantClientCredentials(Scope: string;
  var AccessToken: string; var TokenScope: string;
  var expires_in: integer);
var Response: TOAuth2BearerTokenResponse;
begin
  Response := TOAuth2BearerTokenResponse.Create;
  try
    GrantClientCredentials(Scope,Response);
    AccessToken := Response.access_token;
    expires_in := Response.expires_in;
    TokenScope := Response.scope;
  finally
    Response.Free;
  end;
end;

procedure TOAuth2Client.GrantClientCredentials(Scope: string;
  Response: TOAuth2TokenResponse);
var Params: TStringList;
begin
  {RFC 6749 Client Credentials grant}
  Params := TStringList.Create;
  try
    Params.Values['grant_type'] := 'client_credentials';
    if Scope <> '' then
      Params.Values['scope'] := Scope;
    Post(TokenEndPoint,Params,Response);
  finally
    Params.free;
  end;
end;

procedure TOAuth2Client.GrantUserPasswordCredentials(Scope: string; UserName,
  Password: string; var AccessToken: string; var RefreshToken: string;
  var TokenScope: string; var expires_in: integer);
var Response: TOAuth2BearerTokenResponse;
begin
  Response := TOAuth2BearerTokenResponse.Create;
  try
    GrantUserPasswordCredentials(Scope,UserName, Password,Response);
    AccessToken := Response.access_token;
    RefreshToken := Response.refresh_token;
    expires_in := Response.expires_in;
    TokenScope := Response.scope;
  finally
    Response.Free;
  end;
end;

procedure TOAuth2Client.GrantUserPasswordCredentials(Scope: string; UserName,
  Password: string; Response: TOAuth2TokenResponse);
var Params: TStringList;
begin
  {RFC 6749 Resource Owner Password Credentials Grant}
  Params := TStringList.Create;
  try
    Params.Values['grant_type'] :='password';
    if Scope <> '' then
      Params.Values['scope'] := Scope;
    Params.Values['username'] := UserName;
    Params.Values['password'] := Password;
    Post(TokenEndPoint,Params,Response);
  finally
    Params.free;
  end;
end;

procedure TOAuth2Client.InternalGrantAuthorizationCode(Scope: string);
var URI: TIdURI;
    Params: TOAuth2URLEncodedData;
    guid: TGUID;
begin
  {RFC 6749 Authorization Code Grant}
  if FAuthGrantState <> agIdle then
    OAuth2Error(erOAuth2ClientNotIdle);

  {Assume ResponseHandler already set up}
  FAuthGrantState := agWaitAuthCode;
  URI := TIdURI.Create(AuthEndPoint);
  Params := TOAuth2URLEncodedData.Create;
  try
    Params.AddParam('response_type','code');
    Params.AddParam('client_id',ClientID);
    if Scope <> '' then
      Params.AddParam('scope',Scope);
    if CreateGUID(guid) <> 0 then
      OAuth2Error(erCreateGuidFailed);
    FState := GUIDToString(guid);
    Params.AddParam('state',FState);
    Params.AddParam('redirect_uri',RedirectURI);
    URI.Params := Params.DataString;
    if OpenURL(URI.GetFullURI) then
        FServer.Active := true
    else
      OAuth2Error(erOpenURLFailed,[URI.GetFullURI]);
  finally
    URI.Free;
    Params.Free;
  end;
end;

{Asynchromous - response is processed by HTTP Server OnCommandGet}
procedure TOAuth2Client.GrantAuthorizationCodeAsync(Scope: string;
  ResponseClass: TOAuth2TokenResponseClass);
begin
  CheckMainThread;
  FResponseHandler := TAsyncResponseHandler.Create(self,ResponseClass);
  InternalGrantAuthorizationCode(Scope);
end;

{Asynchromous - response is processed by HTTP Server OnCommandGet}
procedure TOAuth2Client.GrantAuthorizationCodeAsync(Scope: string);
begin
  GrantAuthorizationCodeAsync(Scope,TOAuth2BearerTokenResponse);
end;

procedure TOAuth2Client.GrantAuthorizationCode(Scope: string; var AccessToken,
  RefreshToken: string; var TokenScope: string; var expires_in: integer;
  timeout: cardinal);
var Response: TOAuth2BearerTokenResponse;
begin
  Response := TOAuth2BearerTokenResponse.Create;
  try
    GrantAuthorizationCode(Scope, Response, timeout);
    AccessToken := Response.access_token;
    RefreshToken := Response.refresh_token;
    expires_in := Response.expires_in;
    TokenScope := Response.scope;
  finally
    Response.Free;
  end;
end;

procedure TOAuth2Client.GrantAuthorizationCode(Scope: string;
  Response: TOAuth2TokenResponse; timeout: cardinal);
begin
  FResponseHandler := TSyncResponseHandler.Create(self,Response);
  try
    InternalGrantAuthorizationCode(Scope);
    with TSyncResponseHandler(FResponseHandler) do
    begin
      if WaitFor(timeout) = wrTimeout then
        OAuth2Error(erAuthTimeout);
    end;
  finally
    FResponseHandler.Free;
  end;
end;

procedure TOAuth2Client.ImplicitGrantAsync(Scope: string);
begin
  ImplicitGrantAsync(Scope,TOAuth2BearerTokenResponse);
end;

procedure TOAuth2Client.InternalImplicitGrant(Scope: string);
var URI: TIdURI;
    Params: TOAuth2URLEncodedData;
    guid: TGUID;
begin
  {RFC 6749 Implicit Grant}
  if FAuthGrantState <> agIdle then
    OAuth2Error(erOAuth2ClientNotIdle);

  {Assume Response Handler already setup}
  FAuthGrantState := agWaitAccessCode;
  URI := TIdURI.Create(AuthEndPoint);
  Params := TOAuth2URLEncodedData.Create;
  try
    Params.AddParam('response_type','token');
    Params.AddParam('client_id',ClientID);
    if Scope <> '' then
      Params.AddParam('scope',Scope);
    if CreateGUID(guid) <> 0 then
      OAuth2Error(erCreateGuidFailed);
    FState := GUIDToString(guid);
    Params.AddParam('state',FState);
    Params.AddParam('redirect_uri',RedirectURI);
    URI.Params := Params.DataString;
    if OpenURL(URI.GetFullURI) then
        FServer.Active := true
    else
      OAuth2Error(erOpenURLFailed,[URI.GetFullURI]);
  finally
    URI.Free;
    Params.Free;
  end;
end;

procedure TOAuth2Client.ImplicitGrantAsync(Scope: string;
  ResponseClass: TOAuth2TokenResponseClass);
begin
  CheckMainThread;
  FResponseHandler := TAsyncResponseHandler.Create(self,ResponseClass);
  InternalImplicitGrant(Scope);
end;

procedure TOAuth2Client.ImplicitGrant(Scope: string; Response: TOAuth2TokenResponse;
  timeout: cardinal);
begin
  FResponseHandler := TSyncResponseHandler.Create(self,Response);
  try
    InternalImplicitGrant(Scope);
    with TSyncResponseHandler(FResponseHandler)  do
    begin
      if WaitFor(timeout) = wrTimeout then
        OAuth2Error(erAuthTimeout);
    end;
  finally
    FreeAndNil(FResponseHandler);
  end;
end;

procedure TOAuth2Client.ImplicitGrant(Scope: string; var AccessToken: string;
  var TokenScope: string; var expires_in: integer; timeout: cardinal);
var Response: TOAuth2BearerTokenResponse;
begin
  Response := TOAuth2BearerTokenResponse.Create;
  try
    ImplicitGrant(Scope, Response, timeout);
    AccessToken := Response.access_token;
    expires_in := Response.expires_in;
    TokenScope := Response.scope;
  finally
    Response.Free;
  end;
end;

procedure TOAuth2Client.CancelGrantRequest;
begin
  ResetServer;
end;

procedure TOAuth2Client.RefreshAccessToken(Scope, RefreshToken: string;
  var AccessToken: string; var TokenScope: string; var NewRefreshToken: string;
  var expires_in: integer);
var Response: TOAuth2BearerTokenResponse;
begin
  Response := TOAuth2BearerTokenResponse.Create;
  try
    RefreshAccessToken(Scope,RefreshToken,Response);
    AccessToken := Response.access_token;
    NewRefreshToken := Response.refresh_token;
    expires_in := Response.expires_in;
    TokenScope := Response.scope;
  finally
    Response.Free;
  end;
end;

procedure TOAuth2Client.RefreshAccessToken(Scope, RefreshToken: string;
  Response: TOAuth2TokenResponse);
var Params: TStringList;
begin
  Params := TStringList.Create;
  try
    Params.Values['grant_type'] := 'refresh_token';
    if Scope <> '' then
      Params.Values['scope'] := Scope;
    Params.Values['refresh_token'] := RefreshToken;
    Post(TokenEndPoint,Params,Response);
  finally
    Params.free;
  end;
end;

procedure TOAuth2Client.ExtensionGrant(GrantType: string; aParams: TStrings;
  Response: TOAuth2TokenResponse);
var Params: TStringList;
begin
  Params := TStringList.Create;
  try
    Params.Values['grant_type'] := GrantType;
    Params.AddStrings(aParams);
    Post(TokenEndPoint,Params,Response);
  finally
    Params.free;
  end;
end;

procedure Register;
begin
  RegisterComponents('OAuth2',[TOAuth2Client]);
end;

initialization
{$I oauth2client.lrs}

end.

