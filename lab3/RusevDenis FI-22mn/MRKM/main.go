package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"git.avtor.ua/csg/cryptolib"
	"git.avtor.ua/csg/cryptolib/algorithms"
	"git.avtor.ua/csg/cryptolib/certificate"
	"git.avtor.ua/csg/cryptolib/certificates"
	"git.avtor.ua/csg/cryptolib/keystores"
	"git.avtor.ua/csg/cryptolib/privatekeys"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

type Api struct {
	*echo.Echo
}

type Storage struct {
	KeyStore string //адреса  за якою знаходиться файл
	Slot     string //слот
	Pin      string //пароль
}

type SignRequest struct {
	Data        []byte  //дані що ми хочемо підписати
	Storage     Storage // сховище
	Certificate []byte  // сертифікат
}

type SignResponse struct {
	Cms []byte
}

type VerifyRequest struct {
	Cms []byte
}

type VerifyResponse struct {
	Data []byte
}

func main() {
	go NewApi().Start("localhost:9999")

	time.Sleep(time.Second)

	fmt.Println(Test())
}

func NewApi() *Api {
	s := &Api{echo.New()}
	s.configureRouter()
	return s
}

func (s *Api) configureRouter() {
	s.Use(middleware.CORS())
	s.POST("/sign", s.SignData)
	s.POST("/verify", s.VerifyData)
}

func (s *Api) SignData(c echo.Context) error {
	req := new(SignRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	signData, err := Sign(req.Certificate, req.Data, req.Storage)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, SignResponse{signData})
}

func (s *Api) VerifyData(c echo.Context) error {
	req := new(VerifyRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	data, err := Verify(req.Cms)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, VerifyResponse{Data: data})
}

func Verify(cmsenc []byte) ([]byte, error) {
	algs, _ := algorithms.NewInternationalAlgFactory()

	cms, err := cryptolib.NewCmsAdvanced_DerdataSizeAlgs(cmsenc, len(cmsenc), algs)
	if err != nil {
		return nil, err
	}

	data, err := cms.GetContent()
	if err != nil {
		return nil, err
	}

	err = cms.VerifyBegin(&certificates.CertificateFinder{})
	if err != nil {
		return nil, err
	}

	n, err := cms.GetSignerCount()
	if err != nil {
		return nil, err
	}

	if n > 1 {
		return nil, errors.New("more than 1 signer")
	}

	info, err := cms.VerifySigner(0)
	if err != nil {
		return nil, err
	}
	if info == nil {
		si, _ := cms.GetSigner(0)
		code, _ := si.GetVerificationStatus()

		return nil, errors.New("error code = " + strconv.Itoa(code))
	}

	return data, nil
}

func Sign(cert []byte, data []byte, st Storage) ([]byte, error) {
	fmt.Println("Getting Private key")
	pk, err := GetPrivatekeyFromCert(st, cert)
	if err != nil {
		return nil, err
	}
	fmt.Println("set digest alg")
	err = pk.SetDigestAlg("2.16.840.1.101.3.4.2.1", nil)
	if err != nil {
		return nil, err
	}
	fmt.Println("create cms")
	algs, _ := algorithms.NewInternationalAlgFactory()
	cms, err := cryptolib.NewCmsAdvanced_AttachedAlgs(true, algs)
	if err != nil {
		return nil, err
	}
	fmt.Println("new cert")
	c, err := certificate.NewCertificate_Certblob(cert)
	if err != nil {
		return nil, err
	}
	fmt.Println("Sign Init")
	_, err = cms.AddSigner_CertPrivatekey(c, pk)
	if err != nil {
		return nil, err
	}
	fmt.Println("Sign")
	err = cms.Update(data, len(data))
	if err != nil {
		return nil, err
	}
	fmt.Println("Sign Finished")
	if err := cms.EnsureSigned(); err != nil {
		return nil, err
	}
	fmt.Println("cms encoded")
	return cms.GetEncoded()
}

func GetPrivatekeyFromCert(st Storage, cert []byte) (*privatekeys.PrivateKey, error) {
	algs, _ := algorithms.NewInternationalAlgFactory()
	ksFactory, _ := keystores.NewKeyStoreFactory(algs)

	ks, err := ksFactory.OpenKeyFile(st.KeyStore)
	if err != nil {
		return nil, err
	}

	return GetPrivateKeyFromSlot(ks, st.Slot, st.Pin, cert)
}

func GetPrivateKeyFromSlot(ks *keystores.KeyStore, slot string, pin string, cert []byte) (*privatekeys.PrivateKey, error) {
	sl, err := ks.FindSlot_Idstring(slot)
	if err != nil {
		return nil, err
	}

	if err := ks.Login(sl, pin); err != nil {
		return nil, err
	}
	c, err := certificate.NewCertificate_Certblob(cert)
	if err != nil {
		return nil, err
	}

	return ks.GetPrivateKey_SlotCert(sl, c)
}
