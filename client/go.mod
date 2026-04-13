module github.com/andrewheberle/serverless-ssh-ca/client

go 1.25.0

require (
	codeberg.org/sdassow/atomic v1.2.1
	fyne.io/systray v1.12.0
	github.com/allan-simon/go-singleinstance v0.0.0-20210120080615-d0997106ab37
	github.com/andrewheberle/simplecommand v0.5.1
	github.com/andrewheberle/sshagent v1.0.0
	github.com/bep/simplecobra v0.7.0
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/forfuncsake/krl v0.1.0
	github.com/gen2brain/beeep v0.11.2
	github.com/gorilla/securecookie v1.1.2
	github.com/gorilla/sessions v1.4.0
	github.com/hiddeco/sshsig v0.2.0
	github.com/ndbeals/winssh-pageant v0.0.0-20230609194536-9f88b630ebec
	github.com/oapi-codegen/runtime v1.4.0
	github.com/spf13/pflag v1.0.10
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/crypto v0.50.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sys v0.43.0
	golang.zx2c4.com/wireguard/windows v0.6.1
	sigs.k8s.io/yaml v1.6.0
)

replace github.com/nfnt/resize => ./internal/pkg/resize

require (
	git.sr.ht/~jackmordaunt/go-toast v1.1.2 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/dprotaso/go-yit v0.0.0-20220510233725-9ba8df137936 // indirect
	github.com/esiqveland/notify v0.13.3 // indirect
	github.com/getkin/kin-openapi v0.133.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/gohugoio/gift v0.2.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackmordaunt/icns/v3 v3.0.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-zglob v0.0.6 // indirect
	github.com/mh-cbon/go-msi v0.0.0-20230202123407-9625c3dd3939 // indirect
	github.com/mh-cbon/stringexec v0.0.0-20160727103857-5a080a1a4118 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/oapi-codegen/oapi-codegen/v2 v2.6.0 // indirect
	github.com/oasdiff/yaml v0.0.0-20250309154309-f31be36b4037 // indirect
	github.com/oasdiff/yaml3 v0.0.0-20250309153720-d2182401db90 // indirect
	github.com/perimeterx/marshmallow v1.1.5 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sergeymakinen/go-bmp v1.0.0 // indirect
	github.com/sergeymakinen/go-ico v1.0.0-beta.0 // indirect
	github.com/speakeasy-api/jsonpath v0.6.0 // indirect
	github.com/speakeasy-api/openapi-overlay v0.10.2 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	github.com/tc-hib/go-winres v0.3.3 // indirect
	github.com/tc-hib/winres v0.2.1 // indirect
	github.com/urfave/cli v1.22.17 // indirect
	github.com/urfave/cli/v2 v2.25.7 // indirect
	github.com/vmware-labs/yaml-jsonpath v0.3.2 // indirect
	github.com/woodsbury/decimal128 v1.3.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/image v0.12.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/mh-cbon/go-msi
	github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen
	github.com/tc-hib/go-winres
)
