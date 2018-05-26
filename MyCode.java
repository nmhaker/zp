/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

//org.bouncycastle.ASN1.util.ASN1Dump
import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;
import x509.v3.GuiV3;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Vector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathParameters;
import java.security.cert.CertSelector;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.InhibitAnyPolicyExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.SerialNumber;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import sun.security.util.DerInputStream;
import sun.security.x509.Extension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.PKIXExtensions;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.Time;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.SignerInfo;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attribute;
import sun.security.pkcs10.PKCS10Attributes;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSubjectName;

/**
 *
 * @author Milutinac
 */
public class MyCode extends CodeV3 {

	/**
	 *
	 * @param algorithm_conf
	 * @param extensions_conf
	 * @param extension_rules
	 * @throws GuiException
	 */
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extension_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extension_rules);
	}

	private static KeyStore keyStore = null;
	private static final char[] password = new char[]{'b', 'u', 'k', 'i'};
	private static X509Certificate ETFrootCA = null;

	private static KeyStore ks_ca_certs = null;
	private static KeyStore ks_trusted_ca_certs = null;
	
	/**
	 *
	 * @return
	 */
	@Override
	public Enumeration<String> loadLocalKeystore() {	

		try{
			ks_ca_certs = KeyStore.getInstance("PKCS12");
			ks_ca_certs.load(null, password);
			ks_trusted_ca_certs = KeyStore.getInstance("PKCS12");
			ks_trusted_ca_certs.load(null, password);
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}

		try {
			//  Requesting a KeyStore object
			try {
				keyStore = KeyStore.getInstance("PKCS12");
			} catch (KeyStoreException e) {
				e.printStackTrace();
				access.reportError("Nije dohvatio instancu, KeyStore exception");
			}

			//	Load a keystore if it exists					
			FileInputStream fileInputStream = new FileInputStream("localKeyStore");

			if (password != null) {

				keyStore.load(fileInputStream, password);
				fileInputStream.close();

				try {
					
					Enumeration<String> listaAliasa = keyStore.aliases();
					List<String> lista = new ArrayList<>();
					while(listaAliasa.hasMoreElements())
						lista.add(listaAliasa.nextElement());
					for(String alias : lista){
						X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
						//Check for etf root ca
						if(!checkETFrootCA(cert))		
							//Check if it is ca
							if(checkIsCA(cert)){
								addCaCert(alias, cert);
							}	
//						if(generateChain(cert)){
//							System.out.println("Postoji chain za sertifikat: ");
//							System.out.println(ASN1Dump.dumpAsString(cert));
//						}else{
//							System.out.println("Ne postoji chain za sertifikat: ");
//							System.out.println(ASN1Dump.dumpAsString(cert));
//						}
					}

					return keyStore.aliases();
				} catch (KeyStoreException e) {
					access.reportError("KeyStoreException nije mogao da dohvati aliase");
					return null;
				}
			} else {
				access.reportError("password Local Key Store-a je null!");
				return null;
			}

		}catch(Exception e){
			
			if(e instanceof FileNotFoundException)
				System.out.println("Ne postoji keystore");
			else
				e.printStackTrace();
			
			try {
				if (password != null) {
					keyStore.load(null, password);
				} else {
					access.reportError("Password za Key store je null!");
					return null;
				}

				FileOutputStream fileOutputStream = new FileOutputStream("localKeyStore");

				if (password != null) {
					keyStore.store(fileOutputStream, password);
				} else {
					access.reportError("Password za Key store je null!");
					return null;
				}

				if (fileOutputStream != null) {
					fileOutputStream.close();
				}

				return null;

			} catch (Exception e1) {
				e1.printStackTrace();
				access.reportError("Pravljenje key store-a neuspesno: " + e1.getMessage());
				return null;
			}
		}
}

/**
 *
 */
@Override
	public void resetLocalKeystore() {		
		try{
			if(keyStore != null){
				Enumeration<String> listaAliasa = keyStore.aliases();
				List<String> lista = new ArrayList<>();
				while(listaAliasa.hasMoreElements())
					lista.add(listaAliasa.nextElement());
				for(Iterator<String> iterator = lista.iterator(); iterator.hasNext();){
					keyStore.deleteEntry(iterator.next());
				}
				try {
					FileOutputStream fos = new FileOutputStream("localKeyStore");
					keyStore.store(fos, password);
					fos.close();
				} catch (Exception e) {		
					Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, e);			
				}
			}else{
				access.reportError("resetLocalKeystore() -> Iz nekog razloga keyStore je null");
			}

//			signCert(null);

		}catch(Exception e){
			e.printStackTrace();
			access.reportError("Nije mogao da obrise element: "+e.getMessage());
		}		
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public int loadKeypair(String string) {
		if(keyStore != null){
			try{

				
				if(keyStore.containsAlias(string)){

					X509Certificate x509cert = null;

					x509cert = (X509Certificate) keyStore.getCertificate(string);

					//Moram da izbacim razmake iz stringa...
					StringBuilder sb = new StringBuilder();
					char last = '?';
					for(char c : x509cert.getSubjectDN().toString().toCharArray()){
						if(c != ' ' )									
							sb.append(c);
						else if(c == ' ' && last != ',')
							sb.append(c);
						last = c;
					}
					access.setSubject(sb.toString());
					sb = new StringBuilder();
					last = '?';
					for(char c : x509cert.getIssuerDN().toString().toCharArray()){
						if(c != ' ' )									
							sb.append(c);
						else if(c == ' ' && last != ',')
							sb.append(c);
						last = c;
					}
					access.setIssuer(sb.toString());
					access.setIssuerSignatureAlgorithm(x509cert.getSigAlgName());
					access.setSerialNumber(String.valueOf(x509cert.getSerialNumber()));
					access.setVersion(x509cert.getVersion()-1);
					access.setNotBefore(x509cert.getNotBefore());
					access.setNotAfter(x509cert.getNotAfter());
			
					X509CertImpl certExt = (X509CertImpl)x509cert;
					
					if(certExt == null)  return -1;
					
					try{
						if(certExt.getAuthorityKeyIdentifierExtension()!=null){
							System.out.println("Postavljena ekstenzija AuthorityKeyIdentifier");
							StringBuilder strb = new StringBuilder();
							try{
								for(byte b : ((KeyIdentifier)certExt.getAuthorityKeyIdentifierExtension().get(AuthorityKeyIdentifierExtension.KEY_ID)).getIdentifier())
									strb.append(String.format("%02X", b));
								access.setAuthorityKeyID(strb.toString());
							}catch(Exception e){
								System.out.println("Greska sa AuthorityKeyIdentifierExtension.KEY_ID");
								e.printStackTrace();
							}
							
							try{
								access.setAuthorityIssuer(((X500Name)((GeneralName)((GeneralNames)certExt.getAuthorityKeyIdentifierExtension().get(AuthorityKeyIdentifierExtension.AUTH_NAME)).get(0)).getName()).getCommonName());
							}catch(Exception e){
								System.out.println("Greska sa AuthorityKeyIdentifierExtension.AUTH_NAME");
								e.printStackTrace();
							}
							try{
								access.setAuthoritySerialNumber(((SerialNumber)certExt.getAuthorityKeyIdentifierExtension().get(AuthorityKeyIdentifierExtension.SERIAL_NUMBER)).getNumber().toString());
							}catch(Exception e){
								System.out.println("Greska sa AuthorityKeyIdentifierExtension.SERIAL_NUMBER");
								e.printStackTrace();
							}
							access.setEnabledAuthorityKeyID(true);
							if(certExt.getAuthorityKeyIdentifierExtension().isCritical())
								access.setCritical(Constants.AKID, true);
						}else{
							System.out.println("Nije postavljena ekstenzija AuthorityKeyIdentifier");
						}
						
						if(certExt.getExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()))!=null){
							System.out.println("Postavljena ekstenzija SubjectDirectoryAttributes");
							SubjectDirectoryAttributes sda = null;
							try {
//									
								SubjectDirectoryAttributes sda_in = SubjectDirectoryAttributes.getInstance(certExt.getExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString())).getExtensionValue());
								
								access.setDateOfBirth(((ASN1GeneralizedTime)(((Attribute)(sda_in.getAttributes().get(0))).getAttrValues()).getObjectAt(0)).getTimeString());
								access.setSubjectDirectoryAttribute(0, ((ASN1String)(((Attribute)(sda_in.getAttributes().get(1))).getAttrValues()).getObjectAt(0)).getString());
								access.setSubjectDirectoryAttribute(1, ((ASN1String)(((Attribute)(sda_in.getAttributes().get(2))).getAttrValues()).getObjectAt(0)).getString());
								access.setGender(((ASN1String)(((Attribute)(sda_in.getAttributes().get(3))).getAttrValues()).getObjectAt(0)).getString());
								if(certExt.getExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString())).isCritical())
									access.setCritical(Constants.SDA, true);
							 } catch (Exception e) {
								e.printStackTrace();
								return -1;
							 }
						}else{
							System.out.println("Nije postavljena ekstenzija SubjectDirectoryAttributes");
						}

						if(certExt.getExtension(PKIXExtensions.InhibitAnyPolicy_Id)!=null){
							System.out.println("Postavljena ekstenzija InhibitAnyPolicy");
							access.setCritical(Constants.IAP, true);
							access.setInhibitAnyPolicy(true);
							DerInputStream in = new DerInputStream(certExt.getExtension(PKIXExtensions.InhibitAnyPolicy_Id).getExtensionValue());							
							int skip_certs = in.getInteger();
							access.setSkipCerts(String.valueOf(skip_certs));							
						}else{
							System.out.println("Nije postavljena ekstenzija InhibitAnyPolicy");
						}
						
						
						
					}catch(Exception e){
						e.printStackTrace();
						return -1;
					}
					
					//Generate certificate chain and check if this certificate is trusted, if it is trusted it will be in trusted keystore after chain build
//					access.reportError("chain: "+generateChain((X509Certificate)keyStore.getCertificate(string)));
					//-------------------------------------------

					if(ks_trusted_ca_certs.containsAlias(string) || checkETFrootCA(x509cert)){
						System.out.println("TRUSTED SERTIFIKAT");
						return 2;
					}
					
					if(X509CertImpl.isSelfSigned(x509cert, null)){
						System.out.println("NOT SIGNED SERTIFIKAT");
						return 0;
					}else{
						System.out.println("SIGNED SERTIFIKAT");
						return 1;
					}
					
				}else{
					access.reportError("containsAlias vratio false sto ne bi trebao, jer taj string gui postavlja kad selektujemo keypair/certificate");
					return -1;
				}
			}catch(KeyStoreException e){
				e.printStackTrace();
				access.reportError("containsAlias -> " + e.getMessage());
				return -1;
			}
		}else{
			access.reportError("keyStore je null <- loadKeypair");
			return -1;
		}
	}
	
	HashMap<String, HashMap<String, ?>> ekstenzije = null;

	private boolean generateSelfSignedKeyPairCertificate(String keypair_name){
		try{
			//GENERATE KEY PAIR
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(access.getPublicKeyAlgorithm());

			String signatureAlgorithm = access.getPublicKeyDigestAlgorithm();
			kpg.initialize(Integer.valueOf(access.getPublicKeyParameter()),new SecureRandom());
			KeyPair kp = kpg.generateKeyPair();

			PublicKey pu = kp.getPublic();
			PrivateKey pr = kp.getPrivate();

			//GET SELF SERTIFICATE
			System.out.println("Kreiram polja sertifikata:");
			X509CertInfo info = new X509CertInfo();
			info.set(X509CertInfo.VERSION, new CertificateVersion(access.getVersion()));			
			BigInteger bi = new BigInteger(access.getSerialNumber());
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(bi));
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(signatureAlgorithm)));
			
			System.out.println("getSubject(): "+access.getSubject());
			info.set(X509CertInfo.SUBJECT, new sun.security.x509.X500Name(access.getSubject()));
			info.set(X509CertInfo.KEY, new CertificateX509Key(pu));               
			info.set(X509CertInfo.VALIDITY, new CertificateValidity(access.getNotBefore(), access.getNotAfter()));
			System.out.println("getIssuer(): "+access.getIssuer());
			info.set(X509CertInfo.ISSUER, new sun.security.x509.X500Name(access.getSubject()));

			CertificateExtensions certExt = new CertificateExtensions();
			if(access.getEnabledAuthorityKeyID())
				if(!access.isCritical(Constants.AKID)){
					System.out.println(access.getSubjectCommonName());						
					certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(pu),new GeneralNames().add(new GeneralName(new X500Name("CN="+access.getSubjectCommonName()))),new SerialNumber(bi)));					
				}else{
					AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension(new KeyIdentifier(pu),new sun.security.x509.GeneralNames().add(new GeneralName(new X500Name("CN="+access.getSubjectCommonName()))),new SerialNumber(bi));
					certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(Boolean.TRUE, akie.getExtensionValue()));
				}
				
			String dateOfBirth = access.getDateOfBirth();
			String placeOfBirth = access.getSubjectDirectoryAttribute(0);
			String countryOfCitizenship = access.getSubjectDirectoryAttribute(1);
			String gender = access.getGender();

			Vector<Attribute> attributes = new Vector<>();
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(new DERGeneralizedTime(sdf.parse(dateOfBirth)))));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2"), new DERSet(new DERUTF8String(placeOfBirth))));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4"), new DERSet(new DERPrintableString(countryOfCitizenship))));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3"), new DERSet(new DERPrintableString(gender))));
			
			SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes(attributes);
				
			if(!access.isCritical(Constants.SDA))
				certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), false, sda.getEncoded()) );
			else
				certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), true, sda.getEncoded()) );
			
			if(access.getInhibitAnyPolicy()){	
				certExt.set(InhibitAnyPolicyExtension.NAME, new InhibitAnyPolicyExtension(Integer.valueOf(access.getSkipCerts())));
				System.out.println("Uspesno postavljena ekstenzija InhibitAnyPolicy");
			}
				
					
			info.set(X509CertInfo.EXTENSIONS, certExt);

			X509CertImpl cert = new X509CertImpl(info);
			cert.sign(pr, signatureAlgorithm);
			
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = (X509Certificate)cert;
			
			keyStore.setKeyEntry(keypair_name, pr, password, chain);
				
			FileOutputStream fileOutputStream = new FileOutputStream("localKeyStore");

			keyStore.store(fileOutputStream, password);

			fileOutputStream.close();

			return true;
			
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public boolean saveKeypair(String string) {

		try{
			
			return generateSelfSignedKeyPairCertificate(string);
//			return signCert((X509Certificate)keyStore.getCertificate(string));


		}catch(Exception e){
			e.printStackTrace();
			access.reportError(e.getMessage());
			return false;
		}
				
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public boolean removeKeypair(String string) {
		try{
			keyStore.deleteEntry(string);
			OutputStream fos = new FileOutputStream("localKeyStore");
			keyStore.store(fos, password);
			fos.close();
			return true;
		}catch(Exception e){
			e.printStackTrace();
			access.reportError(e.getMessage());
			return false;
		}
	}
	
	private boolean checkIsCA(X509Certificate cert){
		try{
			return X509CertImpl.toImpl(cert).getBasicConstraintsExtension() != null ? (boolean)X509CertImpl.toImpl(cert).getBasicConstraintsExtension().get(BasicConstraintsExtension.IS_CA) : false;
		}catch(Exception e){
			e.printStackTrace();
			access.reportError(e.getMessage());
			return false;
		}
	}
	
	private boolean addCaCert(String alias, X509Certificate cert){
		if(checkIsCA(cert)){
			try{
				ks_ca_certs.setCertificateEntry(alias, cert);
				return true;
			}catch(Exception e){
				e.printStackTrace();
				return false;
			}
		}else{
			System.out.println("Nije CA");
			return false;
		}
	}

	private boolean checkETFrootCA(X509Certificate cert){
		if(checkIsCA(cert) && X509CertImpl.isSelfSigned(cert, null)){			
			String dn = cert.getIssuerX500Principal().getName();
			String[] key_value_pairs = dn.split(",");
			System.out.println(key_value_pairs[0]);
			String[] cn = key_value_pairs[0].split("=");
			System.out.println(cn[1]);
			if(cn[1].equals("ETFrootCA")){
				if(ETFrootCA == null){
					ETFrootCA = cert;
					System.out.println("Nadjen ETFrootCA sertifikat");
				}else{
					System.out.println("Vec je postavljen ETFrootCA sertifikat!!");
				}
				return true;
			}else{
				System.out.println("Nije nadjen ETFrootCA sertifikat");
				return false;
			}
		}else{
//			System.out.println("Sertifikat nije self Signed -> nije ETF");
			return false;
		}
	}
	
	private boolean generateChain(X509Certificate target){
		try{
			CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
			
//			KeyStore temp_ks = KeyStore.getInstance("PKCS12");
//			temp_ks.load(null, password);
//			Enumeration<String> aliases = keyStore.aliases();
//			while(aliases.hasMoreElements()){
//				String next = aliases.nextElement();
//				temp_ks.setCertificateEntry(next, keyStore.getCertificate(next));
//			}
				
			X509CertSelector certSelector = new X509CertSelector();
			certSelector.setSubject(target.getSubjectX500Principal());
			PKIXBuilderParameters cpp = new PKIXBuilderParameters(keyStore,certSelector);
			PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)cpb.build(cpp);
			if(!result.getCertPath().getCertificates().isEmpty()){
				System.out.println("Chain path: "+result.getCertPath().toString());
				return true;
			}else
				return false;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}
	
	/**
	 *
	 * @param string
	 * @param string1
	 * @param string2
	 * @return
	 */
	@Override
	public boolean importKeypair(String string, String string1, String string2) {
		try{
			FileInputStream fis = new FileInputStream(string1);
			KeyStore iks = KeyStore.getInstance("PKCS12");
			iks.load(fis, string2.toCharArray());	
			fis.close();
			
			try{
				keyStore.setEntry(string, iks.getEntry(iks.aliases().nextElement(), new KeyStore.PasswordProtection(string2.toCharArray())), new KeyStore.PasswordProtection(password));
			}catch(Exception e){
				e.printStackTrace();
			}
			
//			if(iks.isCertificateEntry(iks.aliases().nextElement()))
//				keyStore.setCertificateEntry(string, iks.getCertificate(iks.aliases().nextElement()));
//			else if(iks.isKeyEntry(iks.aliases().nextElement())){
//				try{
//					keyStore.setKeyEntry(string, iks.getKey(iks.aliases().nextElement(), password),password, iks.getCertificateChain(iks.aliases().nextElement()));
//				}catch(Exception e){
//					System.out.println("Pokusano ubaciti kao keyEntry pa nece tako da idemo na certificateEntry");
//					keyStore.setCertificateEntry(string, iks.getCertificate(iks.aliases().nextElement()));
//				}
//			}
			
			//Check for etf root ca
			if(!checkETFrootCA((X509Certificate)iks.getCertificate(iks.aliases().nextElement())))			
				//Check if it is ca
				if(checkIsCA((X509Certificate)iks.getCertificate(iks.aliases().nextElement()))){
					if(!addCaCert(string, (X509Certificate)iks.getCertificate(iks.aliases().nextElement())))
						return false;
				}
			
//			fis.close();
			FileOutputStream fos = new FileOutputStream("localKeyStore");
			keyStore.store(fos, string2.toCharArray());
			fos.close();

			return true;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @param string1
	 * @param string2
	 * @return
	 */
	@Override
	public boolean exportKeypair(String string, String string1, String string2) {
		try{
			KeyStore ksExport = KeyStore.getInstance("PKCS12");
			ksExport.load(null, string2.toCharArray());
			FileOutputStream fos = new FileOutputStream(string1);
			ksExport.setKeyEntry(string, keyStore.getKey(string, password),password, keyStore.getCertificateChain(string));
			ksExport.store(fos, string2.toCharArray());
			fos.close();
			return true;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @param string1
	 * @return
	 */
	@Override
	public boolean importCertificate(String string, String string1) {
		try{
			FileInputStream fis = new FileInputStream(string);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Collection<X509Certificate> chain = (Collection<X509Certificate>) cf.generateCertificates(fis);
			fis.close();
			for(X509Certificate cert : chain){				
				//Check for etf root ca
				if(!checkETFrootCA(cert))
					//Check if it is ca
					if(checkIsCA(cert)){
						if(!addCaCert(string1, cert))
							return false;
					}				
				keyStore.setCertificateEntry(string1, cert);
			}
			FileOutputStream fos = new FileOutputStream("localKeyStore");
			keyStore.store(fos, password);
			fos.close();
			return true;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @param string1
	 * @param i
	 * @param i1
	 * @return
	 */
	@Override
	public boolean exportCertificate(String string, String string1, int i, int i1) {
		try {
			FileOutputStream fos = new FileOutputStream(string);
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(string1);
			if(i1 == 0){
				if(i == 0){
					//DER ENCODED
					byte[] derEncoded = cert.getEncoded();
					fos.write(derEncoded);
					fos.close();
					return true;
				}else if(i == 1){
					//PEM FORMAT
					BASE64Encoder encoder = new BASE64Encoder();
					StringBuilder sb = new StringBuilder();
					sb.append(X509Factory.BEGIN_CERT+"\n");					
					sb.append(encoder.encode(cert.getEncoded())+"\n");
					sb.append(X509Factory.END_CERT);
					fos.write(sb.toString().getBytes());
					fos.close();
					return true;
				}else{
					access.reportError("tip sertifikata za expoprtovanje nepodrzan");
					return false;
				}
			}else if(i1 == 1){
				//PEM FORMAT
				BASE64Encoder encoder = new BASE64Encoder();
				StringBuilder sb = new StringBuilder();
				for(Certificate c : keyStore.getCertificateChain(string1)){
					X509Certificate c1 = (X509Certificate)c;
					sb.append(X509Factory.BEGIN_CERT+"\n");						
					sb.append(encoder.encode(c1.getEncoded())+"\n");
					sb.append(X509Factory.END_CERT);
				}
				fos.write(sb.toString().getBytes());
				fos.close();
				return true;
			}else{
				return false;
			}

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @param string1
	 * @param string2
	 * @return
	 */
	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {
//		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
		try{
			FileOutputStream output = new FileOutputStream(file);
			
			X509Certificate entry = (X509Certificate) (keyStore.getCertificate(keypair_name));			
			PKCS10Attribute pkcs10_attr = new PKCS10Attribute(PKCS9Attribute.CHALLENGE_PASSWORD_OID, entry.getSerialNumber().toString());
			PKCS10Attributes attributes = new PKCS10Attributes(new PKCS10Attribute[]{pkcs10_attr});
			PKCS10 pkcs10 = new PKCS10(entry.getPublicKey(), attributes);
			
			Signature signature = Signature.getInstance(algorithm);
			signature.initSign(((PrivateKeyEntry)keyStore.getEntry(keypair_name,new PasswordProtection(password))).getPrivateKey());
			pkcs10.encodeAndSign(X500Name.asX500Name(entry.getSubjectX500Principal()), signature);
			
			byte[] bytes = pkcs10.getEncoded();
			
			output.write(bytes);
			output.flush();
			output.close();
			
			return true;
			
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
		
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	
	private static PKCS10 importedCSR = null;
	
	@Override
	public String importCSR(String string) {
//		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
		try{
			FileInputStream fis = new FileInputStream(string);
			byte[] bytes = new byte[fis.available()];
			fis.read(bytes);
			fis.close();
			//THIS CONSTRUCTOR VERIFIES ITSELF THE USER!
			PKCS10 pkcs10 = new PKCS10(bytes);
			importedCSR = pkcs10;
			
			StringBuilder sb = new StringBuilder();
			char last = '?';
			for(char c : pkcs10.getSubjectName().toString().toCharArray()){
				if(c != ' ' )									
					sb.append(c);
				else if(c == ' ' && last != ',')
					sb.append(c);
				last = c;
			}
			return sb.toString();
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}		
	}

	private String fixX500Name(String s){
		StringBuilder sb = new StringBuilder();
		char last = '?';
		for(char c : s.toCharArray()){
			if(c != ' ' )									
				sb.append(c);
			else if(c == ' ' && last != ',')
				sb.append(c);
			last = c;
		}
		return sb.toString();
	}
	
	/**
	 *
	 * @param string
	 * @param string1
	 * @param string2
	 * @return
	 */
	@Override
	public boolean signCSR(String file, String keypair, String algorithm) {				
		try{
			//Check if csr is imported
			if(importedCSR != null){
	
				X509Certificate ca = (X509Certificate)keyStore.getCertificate(keypair);
				PrivateKey pr_ca = ((PrivateKeyEntry)keyStore.getEntry(keypair, new PasswordProtection(password))).getPrivateKey();								

				X509CertInfo info = new X509CertInfo();			

				info.set(X509CertInfo.VERSION, new CertificateVersion(access.getVersion()));			
				BigInteger bi = new BigInteger((String) importedCSR.getAttributes().getAttribute("1.2.840.113549.1.9.7").toString());
//				System.out.println(importedCSR.getAttributes());
//				System.out.println(importedCSR.getAttributes().getAttribute("1.2.840.113549.1.9.7"));
//				return false;
				info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(bi));
				info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(access.getPublicKeyDigestAlgorithm())));
				info.set(X509CertInfo.SUBJECT, new X500Name(fixX500Name(access.getSubject())));
				info.set(X509CertInfo.KEY, new CertificateX509Key(importedCSR.getSubjectPublicKeyInfo()));               
				info.set(X509CertInfo.VALIDITY, new CertificateValidity(access.getNotBefore(), access.getNotAfter()));			
				info.set(X509CertInfo.ISSUER, new X500Name(fixX500Name(access.getIssuer())));

				CertificateExtensions certExt = new CertificateExtensions();
				if(access.getEnabledAuthorityKeyID())
					if(!access.isCritical(Constants.AKID)){
						System.out.println(access.getSubjectCommonName());						
						certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(ca.getPublicKey()),new GeneralNames().add(new GeneralName(new X500Name("CN="+access.getSubjectCommonName()))), new SerialNumber(bi)));					
					}else{
						AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension(new KeyIdentifier(ca.getPublicKey()),new sun.security.x509.GeneralNames().add(new GeneralName(new X500Name("CN="+access.getSubjectCommonName()))),new SerialNumber(bi));
						certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(Boolean.TRUE, akie.getExtensionValue()));
					}

				String dateOfBirth = access.getDateOfBirth();
				String placeOfBirth = access.getSubjectDirectoryAttribute(0);
				String countryOfCitizenship = access.getSubjectDirectoryAttribute(1);
				String gender = access.getGender();

				Vector<Attribute> attributes = new Vector<>();
				SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
				if(dateOfBirth!=null && !dateOfBirth.isEmpty())
					attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(new DERGeneralizedTime(sdf.parse(dateOfBirth)))));
				else
					attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(new DERGeneralizedTime(new Date()))));
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2"), new DERSet(new DERUTF8String(placeOfBirth))));
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4"), new DERSet(new DERPrintableString(countryOfCitizenship))));
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3"), new DERSet(new DERPrintableString(gender))));

				SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes(attributes);

				if(!access.isCritical(Constants.SDA))
					certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), false, sda.getEncoded()) );
				else
					certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), true, sda.getEncoded()) );			 
				if(access.getInhibitAnyPolicy())
					certExt.set(InhibitAnyPolicyExtension.NAME, new InhibitAnyPolicyExtension(Integer.valueOf(access.getSkipCerts())));					
				info.set(X509CertInfo.EXTENSIONS, certExt);

				X509CertImpl new_cert = new X509CertImpl(info);
				new_cert.sign(pr_ca, access.getPublicKeyDigestAlgorithm());		
				DerOutputStream dos = new DerOutputStream();
				new_cert.derEncode(dos);
				
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				
				SignerInfo si = new SignerInfo(new X500Name(fixX500Name(access.getIssuer())),
											   ca.getSerialNumber(),
											   AlgorithmId.get(access.getPublicKeyDigestAlgorithm()), 
											   AlgorithmId.get(access.getPublicKeyDigestAlgorithm()),	
											   md.digest(dos.toByteArray()));
				PKCS7 pkcs7 = new PKCS7(new AlgorithmId[]{AlgorithmId.get(access.getPublicKeyDigestAlgorithm())},
										new ContentInfo(ContentInfo.SIGNED_DATA_OID, new DerValue(dos.toByteArray())), 
										new X509Certificate[]{(X509Certificate)new_cert},
										new SignerInfo[]{ si });
				
				DerOutputStream dos2 = new DerOutputStream();
				pkcs7.encodeSignedData(dos2);	
				FileOutputStream fos = new FileOutputStream(file);
				fos.write(dos2.toByteArray());
				fos.flush();
				fos.close();
				return true;
			}else{
				System.out.println("nije ucitan CSR!");
				return false;
			}
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @param string1
	 * @return
	 */
	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try{
			FileInputStream fis = new FileInputStream(file);
			byte[] reply = new byte[fis.available()];
			fis.read(reply);

			PKCS7 pkcs7_reply = new PKCS7(reply);

			PrivateKeyEntry entry = (PrivateKeyEntry)keyStore.getEntry(keypair_name, new PasswordProtection(password));
			PrivateKey pr = entry.getPrivateKey();
			X509CertImpl cert = (X509CertImpl)keyStore.getCertificate(keypair_name);

			System.out.println("Stari sertifikat SN: "+cert.getSerialNumber());
			System.out.println("Novi sertifikati: "+pkcs7_reply.getCertificates()[0].getSerialNumber());
			System.out.println("Stari sertifikati name: "+new X500Name(fixX500Name(cert.getSubjectDN().toString())));
			System.out.println("Novi sertifikati name: "+new X500Name(fixX500Name(pkcs7_reply.getCertificates()[0].getSubjectDN().toString())));
			return false;
			
			Certificate reply_cert = pkcs7_reply.getCertificate(cert.getSerialNumber(), new X500Name(fixX500Name(cert.getSubjectDN().toString())));
			
			

			System.out.println(ASN1Dump.dumpAsString(reply_cert));

			return true;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public boolean canSign(String string) {

		try{
			return checkIsCA((X509Certificate)keyStore.getCertificate(string));
//			if(ks_trusted_ca_certs.containsAlias(string) || checkETFrootCA((X509Certificate)keyStore.getCertificate(string)))
//				return true;
//				
//			if(ks_trusted_ca_certs.containsAlias(string))
//				return true;
//			else 
//				return false;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public String getSubjectInfo(String string) {
		try{
			X509Certificate x509cert = (X509Certificate) keyStore.getCertificate(string);
			StringBuilder sb = new StringBuilder();
			char last = '?';
			for(char c : x509cert.getSubjectDN().toString().toCharArray()){
				if(c != ' ' )									
					sb.append(c);
				else if(c == ' ' && last != ',')
					sb.append(c);
				last = c;
			}
			return sb.toString();
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public String getCertPublicKeyAlgorithm(String string) {
		try{
			X509Certificate x509cert = (X509Certificate) keyStore.getCertificate(string);
			return x509cert.getPublicKey().getAlgorithm();
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public String getCertPublicKeyParameter(String string) {
		try{
			X509Certificate x509cert = (X509Certificate) keyStore.getCertificate(string);
			return String.valueOf(((RSAPublicKey)(x509cert.getPublicKey())).getModulus().bitLength());
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	//FOR DEVELOPMENT ONLY
	
	private boolean signCert(X509Certificate cert){
		try{
			
			X509CertImpl buki = (X509CertImpl)keyStore.getCertificate("buki");
			PrivateKeyEntry entry = (PrivateKeyEntry)keyStore.getEntry("buki", new KeyStore.PasswordProtection("buki".toCharArray()));
			X509CertInfo buki_info = (X509CertInfo)buki.get(X509CertImpl.NAME+"."+X509CertImpl.INFO);		             System.out.println(buki_info);
			Enumeration<String> elementi_buki = buki_info.getElements();			
			
//			DerOutputStream out = new DerOutputStream();			
//			buki.encode(out);		
//			return false;
//			X509CertInfo info = new X509CertInfo(new DerValue(obj.toString()));
						
			if(ETFrootCA == null){
				System.out.println("ETFrootCA je null");
				return false;
			}
			
			X509CertImpl etf_impl = (X509CertImpl)ETFrootCA;
			X509CertInfo etf_info = (X509CertInfo)etf_impl.get(X509CertImpl.NAME+"."+X509CertImpl.INFO);
			Enumeration<String> elementi_etf = etf_info.getElements();		
			
			X509CertInfo info = new X509CertInfo();
			info.set(X509CertInfo.VERSION, new CertificateVersion(etf_impl.getVersion()-1));			
			BigInteger bi = new BigInteger(access.getSerialNumber());
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(bi));
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(access.getPublicKeyDigestAlgorithm())));
			info.set(X509CertInfo.SUBJECT, new X500Name(buki_info.get(X509CertInfo.SUBJECT).toString()));
			info.set(X509CertInfo.KEY, new CertificateX509Key(buki.getPublicKey()));               
			info.set(X509CertInfo.VALIDITY, new CertificateValidity(etf_impl.getNotBefore(), etf_impl.getNotAfter()));
			System.out.println(new X500Name(etf_info.get(X509CertInfo.ISSUER).toString()));
			info.set(X509CertInfo.ISSUER, new X500Name(etf_info.get(X509CertInfo.ISSUER).toString()));
			
			CertificateExtensions certExt = new CertificateExtensions();
			if(access.getEnabledAuthorityKeyID())
				if(!access.isCritical(Constants.AKID)){
					System.out.println(access.getSubjectCommonName());						
					certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(etf_impl.getPublicKey()),new GeneralNames().add(new GeneralName(new X500Name("CN="+access.getSubjectCommonName()))),new SerialNumber(bi)));					
				}else{
					AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension(new KeyIdentifier(etf_impl.getPublicKey()),new sun.security.x509.GeneralNames().add(new GeneralName(new X500Name("CN="+access.getSubjectCommonName()))),new SerialNumber(bi));
					certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(Boolean.TRUE, akie.getExtensionValue()));
				}
				
			String dateOfBirth = access.getDateOfBirth();
			String placeOfBirth = access.getSubjectDirectoryAttribute(0);
			String countryOfCitizenship = access.getSubjectDirectoryAttribute(1);
			String gender = access.getGender();

			Vector<Attribute> attributes = new Vector<>();
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
			if(dateOfBirth!=null && !dateOfBirth.isEmpty())
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(new DERGeneralizedTime(sdf.parse(dateOfBirth)))));
			else
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(new DERGeneralizedTime(new Date()))));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2"), new DERSet(new DERUTF8String(placeOfBirth))));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4"), new DERSet(new DERPrintableString(countryOfCitizenship))));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3"), new DERSet(new DERPrintableString(gender))));
			
			SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes(attributes);
				
			if(!access.isCritical(Constants.SDA))
				certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), false, sda.getEncoded()) );
			else
				certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), true, sda.getEncoded()) );						
			certExt.set(InhibitAnyPolicyExtension.NAME, new InhibitAnyPolicyExtension(Integer.valueOf(access.getSkipCerts())));					
			info.set(X509CertInfo.EXTENSIONS, certExt);
			
			X509CertImpl new_cert = new X509CertImpl(info);
		
			PrivateKey pk_buki = entry.getPrivateKey();
			PrivateKeyEntry pk_etf = (PrivateKeyEntry)keyStore.getEntry("etf", new PasswordProtection("root".toCharArray()));
//			PrivateKy = keyStore.getKey("etf", "root".toCharArray());
			new_cert.sign(pk_etf.getPrivateKey(), access.getPublicKeyDigestAlgorithm());
			
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = (X509Certificate)new_cert;
			
			keyStore.deleteEntry("buki");
			keyStore.setKeyEntry("buki", pk_buki, password, chain);
			
			FileOutputStream fileOutputStream = new FileOutputStream("localKeyStore_safe");
			if(fileOutputStream != null){
				try{
					keyStore.store(fileOutputStream, password);
				}catch(Exception e){
					e.printStackTrace();
					return false;
				}
				fileOutputStream.flush();
				fileOutputStream.close();
				
				fileOutputStream = new FileOutputStream("localKeyStore");
				if(fileOutputStream != null){
					try{
						keyStore.store(fileOutputStream, password);
					}catch(Exception e){
						e.printStackTrace();
						return false;
					}
					fileOutputStream.flush();
					fileOutputStream.close();
				}else{
					System.out.println("fileOutputStream je null");
				}
			}else{
				System.out.println("fileOutputStream je null");
			}			
			return true;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
	}
	
	
	
}
