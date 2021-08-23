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

unit oauth2tokens;

{$mode objfpc}{$H+}

interface

uses Classes, Sysutils, fpjson;

type
      { TOAuth2Response }

    TOAuth2Response = class(TPersistent)
    protected
      procedure ValidateResponse; virtual; abstract;
    public
      procedure ParseJsonResponse(response: TJSONStringType);
      procedure ProcessParams(Params: TStrings);
    end;

    { TTokenResponse }

    TTokenResponse = class(TOAuth2Response)
    private
      FTokenType: string;
      FTokenTypeName: string;
    protected
      procedure ValidateResponse; override;
      procedure SetTokenTypeName(aTokenTypeName: string);
    public
      constructor Create; virtual;
      property TokenTypeName: string read FTokenTypeName;
    published
      property token_type: string read FTokenType write FTokenType;
    end;

    TTokenResponseClass = class of TTokenResponse;

    { TBearerTokenResponse }

    TBearerTokenResponse = class(TTokenResponse)
      { Example Access Token - JSON encoded
            "access_token":"2YotnFZFEjr1zCsicMWpAA",
            "token_type":"example",
            "expires_in":3600,
            "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter":"example_value"
      }
    private const BearerToken = 'bearer';

    private
      FAccessToken: string;
      FExpiresIn: integer;
      FRefreshToken: string;
      FScope: string;
    protected
      procedure ValidateResponse; override;
    public
      constructor Create; override;
    published
      property access_token: string read FAccessToken write FAccessToken;
      property expires_in: integer read FExpiresIn write FExpiresIn;
      property refresh_token: string read FRefreshToken write FRefreshToken;
      property scope: string read FScope write FScope;
    end;

implementation

uses fpjsonrtti, RttiUtils, TypInfo, oauth2errors;

{ TOAuth2Response }

procedure TOAuth2Response.ParseJsonResponse(response: TJSONStringType);
var DeStreamer: TJSONDeStreamer;
begin
  DeStreamer := TJSONDeStreamer.Create(nil);
  try
    DeStreamer.JSONToObject(response,self);
  finally
    DeStreamer.Free;
  end;
  ValidateResponse;
end;

procedure TOAuth2Response.ProcessParams(Params: TStrings);
var i: integer;
  PropInfoList : TPropInfoList;
  ParamIndex: integer;
begin
  PropInfoList := TPropInfoList.Create(self,tkProperties);
  try
    for i := 0 to PropInfoList.Count - 1 do
    begin
      ParamIndex := Params.IndexOfName(PropInfoList[i]^.Name);
      if ParamIndex <> -1 then
      begin
        case PropInfoList[i]^.PropType^.Kind of
        tkInteger:
          SetOrdProp(self,PropInfoList[i],StrToInt(Params.ValueFromIndex[ParamIndex]));
        tkInt64:
          SetOrdProp(self,PropInfoList[i],StrToInt64(Params.ValueFromIndex[ParamIndex]));
        tkFloat:
          SetFloatProp(self,PropInfoList[i],StrToFloat(Params.ValueFromIndex[ParamIndex]));
        tkSString,
        tkLString,
        tkAString:
          SetStrProp(self,PropInfoList[i],Params.ValueFromIndex[ParamIndex]);
        tkBool:
          if CompareText(Params.ValueFromIndex[ParamIndex],'true') <> 0 then
            SetOrdProp(self,PropInfoList[i],Ord(true))
          else
          if CompareText(Params.ValueFromIndex[ParamIndex],'false') <> 0 then
            SetOrdProp(self,PropInfoList[i],Ord(false))
          else
            OAuth2Error(erInvalidPropertyType,[Params.Names[ParamIndex],Params.ValueFromIndex[ParamIndex]]);
        else
          OAuth2Error(erInvalidPropertyType,[Params.Names[ParamIndex],Params.ValueFromIndex[ParamIndex]]);
        end;
      end;
    end;
  finally
    FreeAndNil(PropInfoList);
  end;
  ValidateResponse;
end;

{ TTokenResponse }

procedure TTokenResponse.ValidateResponse;
begin
  if CompareText(token_type,TokenTypeName) <> 0 then
    OAuth2Error(erBadAccessTokenType,[TokenTypeName,token_type]);
end;

procedure TTokenResponse.SetTokenTypeName(aTokenTypeName: string);
begin
  FTokenTypeName := aTokenTypeName;
end;

constructor TTokenResponse.Create;
begin
  inherited Create;
end;

{ TBearerTokenResponse }

procedure TBearerTokenResponse.ValidateResponse;
begin
  inherited;
  if access_token = '' then
    OAuth2Error(erMissingAccessToken);
end;


constructor TBearerTokenResponse.Create;
begin
  inherited Create;
  SetTokenTypeName(BearerToken);
end;



end.

