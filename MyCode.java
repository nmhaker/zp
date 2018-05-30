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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Vector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
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
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.SignerInfo;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attribute;
import sun.security.pkcs10.PKCS10Attributes;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.GeneralNameInterface;

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

	private boolean isTrusted(String alias) throws KeyStoreException{
		try {
             
            Set<Certificate> trustedRootCerts = new HashSet<Certificate>();
            Set<Certificate> intermediateCerts = new HashSet<Certificate>();

			if(ETFrootCA != null){
				trustedRootCerts.add(ETFrootCA);

				Certificate[] chain = keyStore.getCertificateChain(alias);
				for(int i=1; i<chain.length; i++){
					intermediateCerts.add(chain[i]);
				}
			}else{
				System.out.println("Ne mogu da verifikujem chain jer nemam ucitan ETF-ov sertifikat koji je root trusted");
				return false;
			}
			
			X509CertSelector selector = new X509CertSelector();
			selector.setCertificate((X509Certificate) keyStore.getCertificate(alias));
				
			Set<TrustAnchor> trustAnchors = new HashSet<>();
			for(Certificate trusted : trustedRootCerts){
				trustAnchors.add(new TrustAnchor((X509Certificate)trusted, null));
			}

			PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
			pkixParams.setRevocationEnabled(false);

			CertStore intermediateCertStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(intermediateCerts));
			pkixParams.addCertStore(intermediateCertStore);

			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");

           	PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(pkixParams);

			System.out.println("Postoji chain: "+result.getCertPath().toString());

			return true;

        } catch (CertPathBuilderException certPathEx) {
            System.out.println( "Error building certification path: " + ((X509Certificate)keyStore.getCertificate(alias)).getSubjectX500Principal());
			System.out.println( "Erro: " + certPathEx.getMessage());
			return false;
        } catch (Exception ex) {
			System.out.println( "Error verifying the certificate: " + ((X509Certificate)keyStore.getCertificate(alias)).getSubjectX500Principal());
			System.out.println( "Error: " + ex.getMessage());
			return false;
        }       	
	}
	
	/**
	 *
	 * @return
	 */
	@Override
	public Enumeration<String> loadLocalKeystore() {

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
					while (listaAliasa.hasMoreElements()) {
						lista.add(listaAliasa.nextElement());
					}
					for (String alias : lista) {
						X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
						//Check for etf root ca
						checkETFrootCA(cert);
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

		} catch (Exception e) {

			if (e instanceof FileNotFoundException) {
				System.out.println("Ne postoji keystore");
			} else {
				e.printStackTrace();
			}

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
		try {
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
					System.out.println(e.getMessage());
				}
			}else{
				access.reportError("resetLocalKeystore() -> Iz nekog razloga keyStore je null");
			}

		} catch (Exception e) {
			e.printStackTrace();
			access.reportError("Nije mogao da obrise element: " + e.getMessage());
		}
	}

	/**
	 *
	 * @param string
	 * @return
	 */
	@Override
	public int loadKeypair(String string) {
		if (keyStore != null) {
			try {

				if (keyStore.containsAlias(string)) {

					X509Certificate x509cert = null;

					x509cert = (X509Certificate) keyStore.getCertificate(string);

					//Moram da izbacim razmake iz stringa...
					StringBuilder sb = new StringBuilder();
					char last = '?';
					for (char c : x509cert.getSubjectDN().toString().toCharArray()) {
						if (c != ' ') {
							sb.append(c);
						} else if (c == ' ' && last != ',') {
							sb.append(c);
						}
						last = c;
					}
					access.setSubject(sb.toString());
					sb = new StringBuilder();
					last = '?';
					for (char c : x509cert.getIssuerDN().toString().toCharArray()) {
						if (c != ' ') {
							sb.append(c);
						} else if (c == ' ' && last != ',') {
							sb.append(c);
						}
						last = c;
					}
					
					access.setIssuer(sb.toString());
					access.setIssuerSignatureAlgorithm(x509cert.getSigAlgName());
					access.setSerialNumber(String.valueOf(x509cert.getSerialNumber()));
					access.setVersion(x509cert.getVersion() - 1);
					access.setNotBefore(x509cert.getNotBefore());
					access.setNotAfter(x509cert.getNotAfter());

					X509CertImpl certExt = (X509CertImpl) x509cert;

					if (certExt == null) {
						return -1;
					}

					try {
						if (certExt.getAuthorityKeyIdentifierExtension() != null) {
//							System.out.println("Postavljena ekstenzija AuthorityKeyIdentifier");
							StringBuilder strb = new StringBuilder();
							try {
								for (byte b : ((KeyIdentifier) certExt.getAuthorityKeyIdentifierExtension().get(AuthorityKeyIdentifierExtension.KEY_ID)).getIdentifier()) {
									strb.append(String.format("%02X", b));
								}
								access.setAuthorityKeyID(strb.toString());
							} catch (Exception e) {
								System.out.println("Greska sa AuthorityKeyIdentifierExtension.KEY_ID");
								e.printStackTrace();
							}

							try {
								access.setAuthorityIssuer(((X500Name) ((GeneralName) ((GeneralNames) certExt.getAuthorityKeyIdentifierExtension().get(AuthorityKeyIdentifierExtension.AUTH_NAME)).get(0)).getName()).getCommonName());
							} catch (Exception e) {
								System.out.println("Greska sa AuthorityKeyIdentifierExtension.AUTH_NAME");
								e.printStackTrace();
							}
							try {
								access.setAuthoritySerialNumber(((SerialNumber) certExt.getAuthorityKeyIdentifierExtension().get(AuthorityKeyIdentifierExtension.SERIAL_NUMBER)).getNumber().toString());
							} catch (Exception e) {
								System.out.println("Greska sa AuthorityKeyIdentifierExtension.SERIAL_NUMBER");
								e.printStackTrace();
							}
							access.setEnabledAuthorityKeyID(true);
							if (certExt.getAuthorityKeyIdentifierExtension().isCritical()) {
								access.setCritical(Constants.AKID, true);
							}
						} else {
//							System.out.println("Nije postavljena ekstenzija AuthorityKeyIdentifier");
						}

						if (certExt.getExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString())) != null) {
//							System.out.println("Postavljena ekstenzija SubjectDirectoryAttributes");
//							SubjectDirectoryAttributes sda = null;
							try {
//									
								SubjectDirectoryAttributes sda_in = SubjectDirectoryAttributes.getInstance(certExt.getExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString())).getExtensionValue());

								access.setDateOfBirth(((ASN1GeneralizedTime) (((Attribute) (sda_in.getAttributes().get(0))).getAttrValues()).getObjectAt(0)).getTimeString());
								access.setSubjectDirectoryAttribute(0, ((ASN1String) (((Attribute) (sda_in.getAttributes().get(1))).getAttrValues()).getObjectAt(0)).getString());
								access.setSubjectDirectoryAttribute(1, ((ASN1String) (((Attribute) (sda_in.getAttributes().get(2))).getAttrValues()).getObjectAt(0)).getString());
								access.setGender(((ASN1String) (((Attribute) (sda_in.getAttributes().get(3))).getAttrValues()).getObjectAt(0)).getString());
								if (certExt.getExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString())).isCritical()) {
									access.setCritical(Constants.SDA, true);
								}
							} catch (Exception e) {
								e.printStackTrace();
								return -1;
							}
						} else {
//							System.out.println("Nije postavljena ekstenzija SubjectDirectoryAttributes");
						}

						if (certExt.getExtension(PKIXExtensions.InhibitAnyPolicy_Id) != null) {
//							System.out.println("Postavljena ekstenzija InhibitAnyPolicy");
							access.setCritical(Constants.IAP, true);
							access.setInhibitAnyPolicy(true);
							DerInputStream in = new DerInputStream(certExt.getExtension(PKIXExtensions.InhibitAnyPolicy_Id).getExtensionValue());
							int skip_certs = in.getInteger();
							access.setSkipCerts(String.valueOf(skip_certs));
						} else {
//							System.out.println("Nije postavljena ekstenzija InhibitAnyPolicy");
						}

					} catch (Exception e) {
						e.printStackTrace();
						return -1;
					}

					//Generate certificate chain and check if this certificate is trusted
					if(isTrusted(string) && canSign(string)){
						System.out.println("TRUSTED SERTIFIKAT");
						return 2;
					}
					
					if (X509CertImpl.isSelfSigned(x509cert, null)) {
						System.out.println("NOT SIGNED SERTIFIKAT");
						return 0;
					} else {
						System.out.println("SIGNED SERTIFIKAT");
						return 1;
					}

				} else {
					access.reportError("containsAlias vratio false sto ne bi trebao, jer taj string gui postavlja kad selektujemo keypair/certificate");
					return -1;
				}
			} catch (KeyStoreException e) {
				e.printStackTrace();
				access.reportError("containsAlias -> " + e.getMessage());
				return -1;
			}
		} else {
			access.reportError("keyStore je null <- loadKeypair");
			return -1;
		}
	}

	HashMap<String, HashMap<String, ?>> ekstenzije = null;

	private boolean generateSelfSignedKeyPairCertificate(String keypair_name) {
		try {
			//GENERATE KEY PAIR
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(access.getPublicKeyAlgorithm());

			String signatureAlgorithm = access.getPublicKeyDigestAlgorithm();
			kpg.initialize(Integer.valueOf(access.getPublicKeyParameter()), new SecureRandom());
			KeyPair kp = kpg.generateKeyPair();

			PublicKey pu = kp.getPublic();
			PrivateKey pr = kp.getPrivate();

			//GET SELF SERTIFICATE
//			System.out.println("Kreiram polja sertifikata:");
			X509CertInfo info = new X509CertInfo();
			info.set(X509CertInfo.VERSION, new CertificateVersion(access.getVersion()));
			BigInteger bi = new BigInteger(access.getSerialNumber());
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(bi));
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(signatureAlgorithm)));

//			System.out.println("getSubject(): " + access.getSubject());
			info.set(X509CertInfo.SUBJECT, new X500Name(fixX500Name(access.getSubject())));
			info.set(X509CertInfo.KEY, new CertificateX509Key(pu));
			info.set(X509CertInfo.VALIDITY, new CertificateValidity(access.getNotBefore(), access.getNotAfter()));
//			System.out.println("getIssuer(): " + access.getIssuer());
			info.set(X509CertInfo.ISSUER, new X500Name(fixX500Name(access.getSubject())));

			CertificateExtensions certExt = new CertificateExtensions();
			if (access.getEnabledAuthorityKeyID()) {
				if (!access.isCritical(Constants.AKID)) {
					System.out.println(access.getSubjectCommonName());
					certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(pu), new GeneralNames().add(new GeneralName(new X500Name("CN=" + access.getSubjectCommonName()))), new SerialNumber(bi)));
				} else {
					AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension(new KeyIdentifier(pu), new sun.security.x509.GeneralNames().add(new GeneralName(new X500Name("CN=" + access.getSubjectCommonName()))), new SerialNumber(bi));
					certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(Boolean.TRUE, akie.getExtensionValue()));
				}
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

			if (!access.isCritical(Constants.SDA)) {
				certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), false, sda.getEncoded()));
			} else {
				certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), true, sda.getEncoded()));
			}

			if (access.getInhibitAnyPolicy()) {
				certExt.set(InhibitAnyPolicyExtension.NAME, new InhibitAnyPolicyExtension(Integer.valueOf(access.getSkipCerts())));
//				System.out.println("Uspesno postavljena ekstenzija InhibitAnyPolicy");
			}

			info.set(X509CertInfo.EXTENSIONS, certExt);

			X509CertImpl cert = new X509CertImpl(info);
			cert.sign(pr, signatureAlgorithm);

			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = (X509Certificate) cert;

			keyStore.setKeyEntry(keypair_name, pr, password, chain);

			FileOutputStream fileOutputStream = new FileOutputStream("localKeyStore");

			keyStore.store(fileOutputStream, password);

			fileOutputStream.close();

			return true;

		} catch (Exception e) {
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

		try {

			return generateSelfSignedKeyPairCertificate(string);
//			return signCert((X509Certificate)keyStore.getCertificate(string));

		} catch (Exception e) {
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
		try {
			keyStore.deleteEntry(string);
			OutputStream fos = new FileOutputStream("localKeyStore");
			keyStore.store(fos, password);
			fos.close();
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			access.reportError(e.getMessage());
			return false;
		}
	}

	private boolean checkIsCA(X509Certificate cert) {
		try {
			return X509CertImpl.toImpl(cert).getBasicConstraintsExtension() != null ? (boolean) X509CertImpl.toImpl(cert).getBasicConstraintsExtension().get(BasicConstraintsExtension.IS_CA) : false;
		} catch (Exception e) {
			e.printStackTrace();
			access.reportError(e.getMessage());
			return false;
		}
	}

	private boolean checkETFrootCA(X509Certificate cert) {
		if (checkIsCA(cert) && X509CertImpl.isSelfSigned(cert, null)) {
			String dn = cert.getIssuerX500Principal().getName();
			String[] key_value_pairs = dn.split(",");
//			System.out.println(key_value_pairs[0]);
			String[] cn = key_value_pairs[0].split("=");
//			System.out.println(cn[1]);
			if (cn[1].equals("ETFrootCA")) {
				if (ETFrootCA == null) {
					ETFrootCA = cert;
//					System.out.println("Nadjen ETFrootCA sertifikat");
				} 
//				else {
//					System.out.println("Vec je postavljen ETFrootCA sertifikat!!");
//				}
				return true;
			} 
			else {
//				System.out.println("Nije nadjen ETFrootCA sertifikat");
				return false;
			}
		} 
		else {
//			System.out.println("Sertifikat nije self Signed -> nije ETF");
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
		try {
			FileInputStream fis = new FileInputStream(string1);
			KeyStore iks = KeyStore.getInstance("PKCS12");
			iks.load(fis, string2.toCharArray());
			fis.close();

			try {
				keyStore.setEntry(string, iks.getEntry(iks.aliases().nextElement(), new KeyStore.PasswordProtection(string2.toCharArray())), new KeyStore.PasswordProtection(password));
			} catch (Exception e) {
				e.printStackTrace();
			}


			//Check for etf root ca
			checkETFrootCA((X509Certificate) iks.getCertificate(iks.aliases().nextElement()));
			
			FileOutputStream fos = new FileOutputStream("localKeyStore");
			keyStore.store(fos, string2.toCharArray());
			fos.close();

			return true;
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
	public boolean exportKeypair(String string, String string1, String string2) {
		try {
			KeyStore ksExport = KeyStore.getInstance("PKCS12");
			ksExport.load(null, string2.toCharArray());
			FileOutputStream fos = new FileOutputStream(string1);
			ksExport.setKeyEntry(string, keyStore.getKey(string, password), password, keyStore.getCertificateChain(string));
			ksExport.store(fos, string2.toCharArray());
			fos.close();
			return true;
		} catch (Exception e) {
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
		try {
			FileInputStream fis = new FileInputStream(string);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Collection<X509Certificate> chain = (Collection<X509Certificate>) cf.generateCertificates(fis);
			fis.close();
			for (X509Certificate cert : chain) {
				
				//Check for etf root ca
				checkETFrootCA(cert);
				
				keyStore.setCertificateEntry(string1, cert);
				
			}
			FileOutputStream fos = new FileOutputStream("localKeyStore");
			keyStore.store(fos, password);
			fos.close();
			return true;
		} catch (Exception e) {
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
			if (i1 == 0) {
				if (i == 0) {
					//DER ENCODED
					byte[] derEncoded = cert.getEncoded();
					fos.write(derEncoded);
					fos.close();
					return true;
				} else if (i == 1) {
					//PEM FORMAT
					BASE64Encoder encoder = new BASE64Encoder();
					StringBuilder sb = new StringBuilder();
					sb.append(X509Factory.BEGIN_CERT + "\n");
					sb.append(encoder.encode(cert.getEncoded()) + "\n");
					sb.append(X509Factory.END_CERT);
					fos.write(sb.toString().getBytes());
					fos.close();
					return true;
				} else {
					access.reportError("tip sertifikata za exportovanje nepodrzan");
					return false;
				}
			} else if (i1 == 1) {
				//PEM FORMAT
				BASE64Encoder encoder = new BASE64Encoder();
				StringBuilder sb = new StringBuilder();
				for (Certificate c : keyStore.getCertificateChain(string1)) {
					X509Certificate c1 = (X509Certificate) c;
					sb.append(X509Factory.BEGIN_CERT + "\n");
					sb.append(encoder.encode(c1.getEncoded()) + "\n");
					sb.append(X509Factory.END_CERT);
				}
				fos.write(sb.toString().getBytes());
				fos.close();
				return true;
			} else {
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
		try {
			FileOutputStream output = new FileOutputStream(file);

			X509Certificate entry = (X509Certificate) (keyStore.getCertificate(keypair_name));
			PKCS10Attribute pkcs10_attr = new PKCS10Attribute(PKCS9Attribute.CHALLENGE_PASSWORD_OID, entry.getSerialNumber().toString());
			PKCS10Attributes attributes = new PKCS10Attributes(new PKCS10Attribute[]{pkcs10_attr});
			PKCS10 pkcs10 = new PKCS10(entry.getPublicKey(), attributes);

			Signature signature = Signature.getInstance(algorithm);
			signature.initSign(((PrivateKeyEntry) keyStore.getEntry(keypair_name, new PasswordProtection(password))).getPrivateKey());
			pkcs10.encodeAndSign(new X500Name(entry.getSubjectDN().toString()), signature);

			byte[] bytes = pkcs10.getEncoded();

			output.write(bytes);
			output.flush();
			output.close();

			return true;

		} catch (Exception e) {
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
		try {
			FileInputStream fis = new FileInputStream(string);
			byte[] bytes = new byte[fis.available()];
			fis.read(bytes);
			fis.close();
			//THIS CONSTRUCTOR VERIFIES ITSELF THE USER!
			PKCS10 pkcs10 = new PKCS10(bytes);
			importedCSR = pkcs10;

			StringBuilder sb = new StringBuilder();
			char last = '?';
			for (char c : pkcs10.getSubjectName().toString().toCharArray()) {
				if (c != ' ') {
					sb.append(c);
				} else if (c == ' ' && last != ',') {
					sb.append(c);
				}
				last = c;
			}
			return sb.toString();

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private String fixX500Name(String s) {
		StringBuilder sb = new StringBuilder();
		char last = '?';
		for (char c : s.toCharArray()) {
			if (c != ' ') {
				sb.append(c);
			} else if (c == ' ' && last != ',') {
				sb.append(c);
			}
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
		try {
			//Check if csr is imported
			if (importedCSR != null) {

				X509Certificate ca = (X509Certificate) keyStore.getCertificate(keypair);
				PrivateKey pr_ca = ((PrivateKeyEntry) keyStore.getEntry(keypair, new PasswordProtection(password))).getPrivateKey();
				X509CertImpl ca_impl = (X509CertImpl) ca;
				X509CertInfo ca_info = (X509CertInfo) ca_impl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

				X509CertInfo info = new X509CertInfo();

				info.set(X509CertInfo.VERSION, new CertificateVersion(access.getVersion()));
				BigInteger bi = new BigInteger((String) importedCSR.getAttributes().getAttribute("1.2.840.113549.1.9.7").toString());

				info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(bi));
				info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(access.getPublicKeyDigestAlgorithm())));
				info.set(X509CertInfo.SUBJECT, importedCSR.getSubjectName());
				info.set(X509CertInfo.KEY, new CertificateX509Key(importedCSR.getSubjectPublicKeyInfo()));
				info.set(X509CertInfo.VALIDITY, new CertificateValidity(access.getNotBefore(), access.getNotAfter()));
				info.set(X509CertInfo.ISSUER, new X500Name(ca_info.get(X509CertInfo.SUBJECT).toString()));

				CertificateExtensions certExt = new CertificateExtensions();
				if (access.getEnabledAuthorityKeyID()) {
					if (!access.isCritical(Constants.AKID)) {
//						System.out.println(access.getSubjectCommonName());						
						certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(ca.getPublicKey()), new GeneralNames().add(new GeneralName((GeneralNameInterface) ca.getSubjectDN())), new SerialNumber(ca.getSerialNumber())));
					} else {
						AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension(new KeyIdentifier(ca.getPublicKey()), new sun.security.x509.GeneralNames().add(new GeneralName((GeneralNameInterface) ca.getSubjectDN())), new SerialNumber(ca.getSerialNumber()));
						certExt.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(Boolean.TRUE, akie.getExtensionValue()));
					}
				}

				String dateOfBirth = access.getDateOfBirth();
				String placeOfBirth = access.getSubjectDirectoryAttribute(0);
				String countryOfCitizenship = access.getSubjectDirectoryAttribute(1);
				String gender = access.getGender();

				Vector<Attribute> attributes = new Vector<>();
				SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
				if (dateOfBirth != null && !dateOfBirth.isEmpty()) {
					attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(new DERGeneralizedTime(sdf.parse(dateOfBirth)))));
				} else {
					attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(new DERGeneralizedTime(new Date()))));
				}
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2"), new DERSet(new DERUTF8String(placeOfBirth))));
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4"), new DERSet(new DERPrintableString(countryOfCitizenship))));
				attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3"), new DERSet(new DERPrintableString(gender))));

				SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes(attributes);

				// KORISTIM CRITICAL DA BI ODLUCIO DAL DA UOPSTE AKTIVIRAM SDA EKSTENZIJU JER NEMAM DUGME ZA ENABLE
				if (access.isCritical(Constants.SDA)) {
					certExt.set("SubjectDirectoryAttributes", Extension.newExtension(new ObjectIdentifier(org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()), false, sda.getEncoded()));
				}

				// UVEK AUTOMATSKI POD CRITICAL STAVLJENO, TAKO DA AKO SE AKTIVIRA PUCA JAVNI
				if (access.getInhibitAnyPolicy()) {
					certExt.set(InhibitAnyPolicyExtension.NAME, new InhibitAnyPolicyExtension(Integer.valueOf(access.getSkipCerts())));
				}

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
				
				X509Certificate[] chain = new X509Certificate[keyStore.getCertificateChain(keypair).length+1];
				chain[0] = (X509Certificate)new_cert;

				for(int i=1; i<=keyStore.getCertificateChain(keypair).length; i++){
					chain[i] = (X509Certificate)keyStore.getCertificateChain(keypair)[i-1];
				}
				
				PKCS7 pkcs7 = new PKCS7(new AlgorithmId[]{AlgorithmId.get(access.getPublicKeyDigestAlgorithm())},
					new ContentInfo(ContentInfo.SIGNED_DATA_OID, new DerValue(dos.toByteArray())),
					chain,
					new SignerInfo[]{si});

				DerOutputStream dos2 = new DerOutputStream();
				pkcs7.encodeSignedData(dos2);
				FileOutputStream fos = new FileOutputStream(file);
				fos.write(dos2.toByteArray());
				fos.flush();
				fos.close();
				return true;
			} else {
				System.out.println("nije ucitan CSR!");
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
	 * @return
	 */
	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try {
			FileInputStream fis = new FileInputStream(file);
			byte[] reply = new byte[fis.available()];
			fis.read(reply);

			PKCS7 pkcs7_reply = new PKCS7(reply);

			PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(keypair_name, new PasswordProtection(password));
			PrivateKey pr = entry.getPrivateKey();
			X509CertImpl cert = (X509CertImpl) keyStore.getCertificate(keypair_name);

			X509Certificate[] reply_chain = pkcs7_reply.getCertificates();

			X509Certificate[] reverse_reply_chain = new X509Certificate[reply_chain.length];
			for(int i=reply_chain.length-1, j=0 ; i>=0; i--,j++){
				System.out.println("REPLY_CHAIN["+i+"] "+reply_chain[i].getSubjectX500Principal());
				reverse_reply_chain[j] = reply_chain[i];
			}

			if (reply_chain != null) {

				keyStore.deleteEntry(keypair_name);
				keyStore.setKeyEntry(keypair_name, pr, password, reverse_reply_chain);

				FileOutputStream fos = new FileOutputStream("localKeyStore");
				keyStore.store(fos, password);
				fos.flush();
				fos.close();

				return true;
			} else {
				access.reportError("reply certificate got from ca reply is null");
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
	 * @return
	 */
	@Override
	public boolean canSign(String string) {

		try {

			return checkIsCA((X509Certificate) keyStore.getCertificate(string));

		} catch (Exception e) {
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
		try {
			X509Certificate x509cert = (X509Certificate) keyStore.getCertificate(string);
			StringBuilder sb = new StringBuilder();
			char last = '?';
			for (char c : x509cert.getSubjectDN().toString().toCharArray()) {
				if (c != ' ') {
					sb.append(c);
				} else if (c == ' ' && last != ',') {
					sb.append(c);
				}
				last = c;
			}
			return sb.toString();
		} catch (Exception e) {
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
		try {
			X509Certificate x509cert = (X509Certificate) keyStore.getCertificate(string);
			return x509cert.getPublicKey().getAlgorithm();
		} catch (Exception e) {
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
		try {
			X509Certificate x509cert = (X509Certificate) keyStore.getCertificate(string);
			return String.valueOf(((RSAPublicKey) (x509cert.getPublicKey())).getModulus().bitLength());
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
