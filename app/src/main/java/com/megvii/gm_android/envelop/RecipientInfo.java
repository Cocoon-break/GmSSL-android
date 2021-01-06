package com.megvii.gm_android.envelop;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;

public class RecipientInfo extends ASN1Object {
    private ASN1Integer version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private ASN1OctetString encryptedKey;
    private DERSequence encryptAlg;
    private String sm2_public_encrypt_oid = "1.2.156.10197.1.301.3";

    // 版本号
    public void setVersion(int version) {
        this.version = new ASN1Integer(version);
    }

    // 证书颁发信息
    public void setIssue(IssuerAndSerialNumber issue) {
        this.issuerAndSerialNumber = issue;
    }

    // SM2 加密之后的内容
    public void setEncryptedKey(byte[] content) {
        this.encryptedKey = new DEROctetString(content);
    }


    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector algVector = new ASN1EncodableVector();
        algVector.add(new ASN1ObjectIdentifier(sm2_public_encrypt_oid));
        this.encryptAlg = new DERSequence(algVector);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(version);
        vector.add(issuerAndSerialNumber);
        vector.add(encryptAlg);
        vector.add(encryptedKey);
        return new DERSet(new DERSequence(vector));
    }

    public static class IssuerAndSerialNumber extends ASN1Object {
        private String countryOid = "2.5.4.6";
        private String organizationOid = "2.5.4.10";
        private String commonOid = "2.5.4.3";

        private ASN1Integer serialNum;
        private DERSet countryName;
        private DERSet organizationName;
        private DERSet commonName;

        /*参数来自公钥证书*/
        public IssuerAndSerialNumber(BigInteger serialNum, String countryTag, String organizationTag, String commonTag) {
            this.serialNum = new ASN1Integer(serialNum);
            this.countryName = genDERSet(countryOid, countryTag);
            this.organizationName = genDERSet(organizationOid, organizationTag);
            this.commonName = genDERSet(commonOid, commonTag);
        }

        /*证书序列号*/
        public void setSerialNum(BigInteger serialNum) {
            this.serialNum = new ASN1Integer(serialNum);
        }

        private DERSet genDERSet(String oid, String ps) {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1ObjectIdentifier(oid));
            vector.add(new DERPrintableString(ps));
            return new DERSet(new DERSequence(vector));
        }

        /**
         * SET (1 elem)
         * SEQUENCE (2 elem)
         * OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
         * PrintableString CN
         */
        public void setCountryName(String ps) {
            this.countryName = genDERSet(countryOid, ps);
        }

        /**
         * SET (1 elem)
         * SEQUENCE (2 elem)
         * OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
         * PrintableString GLCTID01
         */
        public void setOrganizationName(String ps) {
            this.organizationName = genDERSet(organizationOid, ps);
        }

        /**
         * SET (1 elem)
         * SEQUENCE (2 elem)
         * OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
         * PrintableString GLCA01
         */
        public void setCommonName(String ps) {
            this.commonName = genDERSet(commonOid, ps);
        }


        public ASN1Primitive toASN1Primitive() {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(this.countryName);
            vector.add(this.organizationName);
            vector.add(this.commonName);
            DERSequence info = new DERSequence(vector);

            ASN1EncodableVector all = new ASN1EncodableVector();
            all.add(info);
            all.add(this.serialNum);
            return new DERSequence(all);
        }
    }
}
