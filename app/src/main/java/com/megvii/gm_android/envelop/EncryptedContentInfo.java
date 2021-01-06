package com.megvii.gm_android.envelop;

import org.bouncycastle.asn1.*;

public class EncryptedContentInfo extends ASN1Object {
    /*国密标准GM/T 0010 定义数据类型data oid 为 1.2.156.10197.6.1.4.2.1*/
    private String GB_DATA_OID = "1.2.156.10197.6.1.4.2.1";

    /* 国密SM4相关oid */
    private String SM4_OID = "1.2.156.10197.1.104";
    private String SM4_ECB_OID = "1.2.156.10197.1.104.1";
    private String SM4_CCB_OID = "1.2.156.10197.1.104.2";

    private ASN1ObjectIdentifier contentType = new ASN1ObjectIdentifier(GB_DATA_OID);

    private DERTaggedObject contentTag;

    /**
     * @param cipher 对称加密，加密之后的内容。加密方式为SM4_ECB
     *               根据一所提供文档只传一项数据所以DERTaggedObject的第二个参数为0
     */
    public void setEncryptionContent(byte[] cipher) {
        ASN1OctetString encryptedContent = new DEROctetString(cipher);
        this.contentTag = new DERTaggedObject(false, 0, encryptedContent);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector encryptionAlgorithmVector = new ASN1EncodableVector();
        // 根据一所提供的文档OID为SM4_OID
        encryptionAlgorithmVector.add(new ASN1ObjectIdentifier(SM4_OID));
        DERSequence encryptionAlgorithm = new DERSequence(encryptionAlgorithmVector);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(contentType);
        vector.add(encryptionAlgorithm);
        vector.add(contentTag);
        return new DERSequence(vector);
    }
}
