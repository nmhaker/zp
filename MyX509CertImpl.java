/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import sun.security.x509.X509CertImpl;
import implementation.SubjectDirectoryAttributesExtension;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CRLDistributionPointsExtension;
import sun.security.x509.CertificatePoliciesExtension;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.Extension;
import sun.security.x509.InhibitAnyPolicyExtension;
import sun.security.x509.IssuerAlternativeNameExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.NameConstraintsExtension;
import sun.security.x509.PKIXExtensions;
import sun.security.x509.PolicyConstraintsExtension;
import sun.security.x509.PolicyMappingsExtension;
import sun.security.x509.PrivateKeyUsageExtension;
import sun.security.x509.SerialNumber;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;
/**
 *
 * @author Milutinac
 */
public class MyX509CertImpl extends X509CertImpl{

	private X509CertImpl delegate;

	public MyX509CertImpl(X509CertImpl delegate) {
		this.delegate = delegate;
	}		
	
	public SubjectDirectoryAttributesExtension getSubjectDirectoryAttributesExtension(){
		return (SubjectDirectoryAttributesExtension)getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id);
	}
	public InhibitAnyPolicyExtension getInhibitAnyPolicyExtension(){
		return (InhibitAnyPolicyExtension)getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id);
	}

	@Override
	public String getFingerprint(String string) {
		return delegate.getFingerprint(string); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public AuthorityInfoAccessExtension getAuthorityInfoAccessExtension() {
		return delegate.getAuthorityInfoAccessExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public synchronized Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
		return delegate.getIssuerAlternativeNames(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public synchronized Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
		return delegate.getSubjectAlternativeNames(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public int getBasicConstraints() {
		return delegate.getBasicConstraints(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public synchronized List<String> getExtendedKeyUsage() throws CertificateParsingException {
		return delegate.getExtendedKeyUsage(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public boolean[] getKeyUsage() {
		return delegate.getKeyUsage(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public byte[] getExtensionValue(String string) {
		return delegate.getExtensionValue(string); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Extension getUnparseableExtension(ObjectIdentifier oi) {
		return delegate.getUnparseableExtension(oi); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Extension getExtension(ObjectIdentifier oi) {
		return delegate.getExtension(oi); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Set<String> getNonCriticalExtensionOIDs() {
		return delegate.getNonCriticalExtensionOIDs(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Set<String> getCriticalExtensionOIDs() {
		return delegate.getCriticalExtensionOIDs(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public boolean hasUnsupportedCriticalExtension() {
		return delegate.hasUnsupportedCriticalExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public CRLDistributionPointsExtension getCRLDistributionPointsExtension() {
		return delegate.getCRLDistributionPointsExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public SubjectKeyIdentifierExtension getSubjectKeyIdentifierExtension() {
		return delegate.getSubjectKeyIdentifierExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public SubjectAlternativeNameExtension getSubjectAlternativeNameExtension() {
		return delegate.getSubjectAlternativeNameExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public PrivateKeyUsageExtension getPrivateKeyUsageExtension() {
		return delegate.getPrivateKeyUsageExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public PolicyMappingsExtension getPolicyMappingsExtension() {
		return delegate.getPolicyMappingsExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public PolicyConstraintsExtension getPolicyConstraintsExtension() {
		return delegate.getPolicyConstraintsExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public NameConstraintsExtension getNameConstraintsExtension() {
		return delegate.getNameConstraintsExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public IssuerAlternativeNameExtension getIssuerAlternativeNameExtension() {
		return delegate.getIssuerAlternativeNameExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public ExtendedKeyUsageExtension getExtendedKeyUsageExtension() {
		return delegate.getExtendedKeyUsageExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public CertificatePoliciesExtension getCertificatePoliciesExtension() {
		return delegate.getCertificatePoliciesExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public BasicConstraintsExtension getBasicConstraintsExtension() {
		return delegate.getBasicConstraintsExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public AuthorityKeyIdentifierExtension getAuthorityKeyIdentifierExtension() {
		return delegate.getAuthorityKeyIdentifierExtension(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public KeyIdentifier getSubjectKeyId() {
		return delegate.getSubjectKeyId(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public KeyIdentifier getAuthKeyId() {
		return delegate.getAuthKeyId(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public boolean[] getSubjectUniqueID() {
		return delegate.getSubjectUniqueID(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public boolean[] getIssuerUniqueID() {
		return delegate.getIssuerUniqueID(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public byte[] getSigAlgParams() {
		return delegate.getSigAlgParams(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public String getSigAlgOID() {
		return delegate.getSigAlgOID(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public String getSigAlgName() {
		return delegate.getSigAlgName(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public byte[] getSignature() {
		return delegate.getSignature(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public byte[] getTBSCertificate() throws CertificateEncodingException {
		return delegate.getTBSCertificate(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Date getNotAfter() {
		return delegate.getNotAfter(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Date getNotBefore() {
		return delegate.getNotBefore(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public X500Principal getIssuerX500Principal() {
		return delegate.getIssuerX500Principal(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Principal getIssuerDN() {
		return delegate.getIssuerDN(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public X500Principal getSubjectX500Principal() {
		return delegate.getSubjectX500Principal(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Principal getSubjectDN() {
		return delegate.getSubjectDN(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public SerialNumber getSerialNumberObject() {
		return delegate.getSerialNumberObject(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public BigInteger getSerialNumber() {
		return delegate.getSerialNumber(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public int getVersion() {
		return delegate.getVersion(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public PublicKey getPublicKey() {
		return delegate.getPublicKey(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public String toString() {
		return delegate.toString(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public String getName() {
		return delegate.getName(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Enumeration<String> getElements() {
		return delegate.getElements(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void delete(String string) throws CertificateException, IOException {
		delegate.delete(string); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void set(String string, Object o) throws CertificateException, IOException {
		delegate.set(string, o); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Object get(String string) throws CertificateParsingException {
		return delegate.get(string); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
		delegate.checkValidity(date); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
		delegate.checkValidity(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void sign(PrivateKey pk, String string, String string1) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
		delegate.sign(pk, string, string1); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void sign(PrivateKey pk, String string) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
		delegate.sign(pk, string); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public synchronized void verify(PublicKey pk, Provider prvdr) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		delegate.verify(pk, prvdr); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public synchronized void verify(PublicKey pk, String string) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
		delegate.verify(pk, string); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void verify(PublicKey pk) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
		delegate.verify(pk); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public byte[] getEncodedInternal() throws CertificateEncodingException {
		return delegate.getEncodedInternal(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public byte[] getEncoded() throws CertificateEncodingException {
		return delegate.getEncoded(); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void derEncode(OutputStream out) throws IOException {
		delegate.derEncode(out); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void encode(OutputStream out) throws CertificateEncodingException {
		delegate.encode(out); //To change body of generated methods, choose Tools | Templates.
	}
	
	
}
