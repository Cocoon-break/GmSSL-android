package com.megvii.gm_android.envelop;

import org.bouncycastle.asn1.*;

public class EnvelopData extends ASN1Object {

    private String envelopedDataOid = "1.2.156.10197.6.1.4.2.3";

    private ASN1Integer version;
    private RecipientInfo recipientInfo;
    private EncryptedContentInfo encryptedContent;

    public void setVersion(int version) {
        this.version = new ASN1Integer(version);
    }

    public void setRecipientInfo(RecipientInfo recipientInfo) {
        this.recipientInfo = recipientInfo;
    }

    public void setEncryptedContent(EncryptedContentInfo encryptedContent) {
        this.encryptedContent = encryptedContent;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(version);
        vector.add(recipientInfo);
        vector.add(encryptedContent);
        DERSequence sq = new DERSequence(vector);
        DERTaggedObject tag = new DERTaggedObject(true, 0, sq);

        ASN1EncodableVector all = new ASN1EncodableVector();
        all.add(new ASN1ObjectIdentifier(envelopedDataOid));
        all.add(tag);
        return new DERSequence(all);
    }
}
