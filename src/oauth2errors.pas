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

unit oauth2errors;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, oauth2tokens;

type
    TOAuth2ErrorCodes = (
      erUnexpectedState,
      erMissingAuthCode,
      erBadAccessTokenType,
      erCreateGuidFailed,
      erOpenURLFailed,
      erAuthTimeout,
      erOAuth2ClientNotIdle,
      erMissingAccessToken,
      erInvalidPropertyType,
      erNotMainThread
    );

    TOAuth2Errors = (oeInvalidRequest,  {The request is missing a required parameter, includes an
                                         unsupported parameter value (other than grant type),
                                         repeats a parameter, includes multiple credentials,
                                         utilizes more than one mechanism for authenticating the
                                         client, or is otherwise malformed.}

                     oeInvalidClient,  {Client authentication failed (e.g., unknown client, no
                                         client authentication included, or unsupported
                                         authentication method).  The authorization server MAY
                                         return an HTTP 401 (Unauthorized) status code to indicate
                                         which HTTP authentication schemes are supported.  If the
                                         client attempted to authenticate via the "Authorization"
                                         request header field, the authorization server MUST
                                         respond with an HTTP 401 (Unauthorized) status code and
                                         include the "WWW-Authenticate" response header field
                                         matching the authentication scheme used by the client.}

                     oeInvalidGrant,  {The provided authorization grant (e.g., authorization
                                       code, resource owner credentials) or refresh token is
                                       invalid, expired, revoked, does not match the redirection
                                       URI used in the authorization request, or was issued to
                                       another client.}

                     oeInvalidAuthClient,  {The authenticated client is not authorized to use this
                                       authorization grant type.}

                     oeUnsupportedGrant, {The authorization grant type is not supported by the
                                          authorization server}

                     oeInvalidScope,  {The requested scope is invalid, unknown, malformed, or
                                      exceeds the scope granted by the resource owner.}

                     oeUnknown);      {none of the above}

    TOAuth2ErrorData = record
      StatusCode: integer;
      ErrorMessage: string;
      ErrorCode: TOAuth2Errors;
      Error: string;
      Description: string;
      ErrorURI: string;
    end;

    EOAuth2ClientError = class(Exception);

    { EOAuth2Exception }

    EOAuth2Exception = class(EOAuth2ClientError)
    private type

      { TErrorInfo }

      TErrorInfo = class(TOAuth2Response)
      {  Example Error Response - JSON encoded
             "error":"invalid_request"
      }
      private
        FError: string;
        FErrorDescription: string;
        FErrorURI: string;
      protected
        procedure ValidateResponse; override;
      public
        constructor Create(responseStr: string); overload;
        constructor Create(Params: TStrings); overload;
      published
        property error: string read FError write FError;
        property error_description: string read FErrorDescription write FErrorDescription;
        property error_uri: string read FErrorURI write FErrorURI;
      end;

    private
      FErrorCode: TOAuth2Errors;
      FErrorResponse: TErrorInfo;
      FStatusCode: integer;
      function GetDescription: string;
      function GetError: string;
      function GetErrorURI: string;
      procedure SetErrorCode(theError: string);
    public
      constructor Create(StatusCode: integer; responseText, responseBody: string); overload;
      constructor Create(Params: TStrings); overload;
      constructor Create(data: TOAuth2ErrorData); overload;
      destructor Destroy; override;
      procedure GetErrorData(var data: TOAuth2ErrorData);
      property StatusCode: integer read FStatusCode;
      property ErrorCode: TOAuth2Errors read FErrorCode;
      property Error: string read GetError;
      property Description: string read GetDescription;
      property ErrorURI: string read GetErrorURI;
    end;

procedure OAuth2Error(ErrorCode: TOAuth2ErrorCodes; args: array of const); overload;
procedure OAuth2Error(ErrorCode: TOAuth2ErrorCodes); overload;

implementation

uses fpjsonrtti;

resourcestring
  {Used with EOAuth2Exception}
  SOAuth2ResponseError = 'Status Code %d %s - OAuth2 Error (%s) %s';
  SOuth2OtherException = 'Status Code %d - Unknown OAuth2 Error';
  SOAuthErrorMessage   = 'Authorisation Code Request Error - %s - %s';

  {used with EOauth2ClientError}
  SUnexpectedState            = 'Unexpected State Parameter - attempt at forgery? Expected "%s", received "%s"';
  SMissingAuthCode            = 'No Authorisation Code contained in response to authorisation code request';
  SBadAccessTokenType         = 'Unexpected Access Token Type - expected %s found %s';
  SCreateGuidFailed           = 'Create GUID Failed';
  SOpenURLFailed              = 'Call to OpenURL Failed for %s';
  SAuthTimeout                = 'Authorization Grant Timeout';
  SOAuth2ClientNotIdle        = 'OAuth2 Client is not idle';
  SMissingAccessToken         = 'Access Token not present in response';
  SInvalidPropertyType        = 'Unsupported property type or value for property %s - value = "%s"';
  SNotMainThread              = 'Method must be called from the main thread only';

const
  OAuth2ErrorMessages: array [TOAuth2ErrorCodes] of string = (
    SUnexpectedState,
    SMissingAuthCode,
    SBadAccessTokenType,
    SCreateGuidFailed,
    SOpenURLFailed,
    SAuthTimeout,
    SOAuth2ClientNotIdle,
    SMissingAccessToken,
    SInvalidPropertyType,
    SNotMainThread
    );

function GetErrorMessage(ErrorCode: TOAuth2ErrorCodes): string;
begin
  Result := OAuth2ErrorMessages[ErrorCode];
end;


procedure OAuth2Error(ErrorCode: TOAuth2ErrorCodes; args: array of const);
begin
  raise EOAuth2ClientError.CreateFMT(GetErrorMessage(ErrorCode),args);
end;

procedure OAuth2Error(ErrorCode: TOAuth2ErrorCodes);
begin
  OAuth2Error(Errorcode,[nil]);
end;

{ EOAuth2Exception.TErrorInfo }

procedure EOAuth2Exception.TErrorInfo.ValidateResponse;
begin
  //do nothing
end;

constructor EOAuth2Exception.TErrorInfo.Create(responseStr: string);
begin
  inherited Create;
  ParseJsonResponse(responseStr);
end;

constructor EOAuth2Exception.TErrorInfo.Create(Params: TStrings);
begin
  inherited Create;
  ProcessParams(Params);
end;

{ EOAuth2Exception }

function EOAuth2Exception.GetDescription: string;
begin
  Result := FErrorResponse.FErrorDescription;
end;

function EOAuth2Exception.GetError: string;
begin
  Result := FErrorResponse.error;
end;

function EOAuth2Exception.GetErrorURI: string;
begin
  Result := FErrorResponse.error_uri;
end;

procedure EOAuth2Exception.SetErrorCode(theError: string);
begin
  FErrorCode := oeUnknown;
  if theError = 'invalid_request' then
    FErrorCode := oeInvalidRequest
  else
  if theError = 'invalid_client' then
    FErrorCode := oeInvalidClient
  else
  if theError = 'invalid_grant' then
    FErrorCode := oeInvalidGrant
  else
  if theError = 'unauthorized_client' then
    FErrorCode := oeInvalidAuthClient
  else
  if theError = 'oeUnsupportedGrant' then
    FErrorCode := oeInvalidAuthClient
  else
  if theError = 'invalid_scope' then
    FErrorCode := oeInvalidScope;
end;

constructor EOAuth2Exception.Create(StatusCode: integer; responseText,
  responseBody: string);
begin
  FStatusCode := StatusCode;
  FErrorResponse := TErrorInfo.Create(responseBody);
  if StatusCode = 400 {Bad Request} then
  begin
   inherited CreateFmt(SOAuth2ResponseError,[StatusCode,responseText,
                                             FErrorResponse.error,
                                             FErrorResponse.error_description]);
   SetErrorCode(FErrorResponse.error);
  end
  else
    inherited CreateFmt(SOuth2OtherException,[StatusCode]);
end;

constructor EOAuth2Exception.Create(Params: TStrings);
begin
  FErrorResponse := TErrorInfo.Create(Params);
  inherited CreateFmt(SOAuthErrorMessage,[FErrorResponse.error,
                                          FErrorResponse.error_description]);
  SetErrorCode(FErrorResponse.error);
end;

constructor EOAuth2Exception.Create(data: TOAuth2ErrorData);
begin
  FStatusCode := data.StatusCode;
  FErrorCode := data.ErrorCode;
  FErrorResponse.error := data.Error;
  FErrorResponse.error_description := data.Description;
  FErrorResponse.error_uri := data.ErrorURI;
  inherited Create(data.ErrorMessage);
end;

destructor EOAuth2Exception.Destroy;
begin
  if FErrorResponse <> nil then
    FErrorResponse.free;
  inherited Destroy;
end;

procedure EOAuth2Exception.GetErrorData(var data: TOAuth2ErrorData);
begin
  data.StatusCode := StatusCode;
  data.ErrorMessage := Message;
  data.ErrorCode := ErrorCode;
  data.Error := Error;
  data.Description := Description;
  data.ErrorURI := ErrorURI;
end;


end.

