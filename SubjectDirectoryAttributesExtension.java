/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import sun.security.util.DerOutputStream;
import sun.security.x509.AttributeNameEnumeration;
import sun.security.x509.Extension;
import sun.security.x509.CertAttrSet;
import sun.security.x509.PKIXExtensions;

/**
 *
 * @author Milutinac
 */
public class SubjectDirectoryAttributesExtension extends Extension implements CertAttrSet<String>{

	public static final String IDENT = "x509.info.extensions.SubjectDirectoryAttributes";
	public static final String NAME = "SubjectDirectoryAttributes";	
	
	public static final String DATE_OF_BIRTH = "DateOfBirth";
	public static final String PLACE_OF_BIRTH = "PlaceOfBirth";
	public static final String COUNTRY_OF_CITIZENSHIP = "CountryOfCitizenship";
	public static final String GENDER = "Gender";
	
	//Private members	
	String dateOfBirth = null;
	String placeOfBirth = null;
	String countryOfCitizenship = null;
	String gender = null;	

	
	public SubjectDirectoryAttributesExtension(String dateOfBirth, String placeOfBirth,	String countryOfCitizenship,String gender)    throws IOException
	{
		this(Boolean.FALSE, dateOfBirth, placeOfBirth, countryOfCitizenship, gender);
	}
	public SubjectDirectoryAttributesExtension(Boolean critical, String dateOfBirth, String placeOfBirth,	String countryOfCitizenship,String gender)throws IOException {
		this.dateOfBirth = dateOfBirth;
		this.placeOfBirth = placeOfBirth;
		this.countryOfCitizenship = countryOfCitizenship;
		this.gender = gender;
		this.extensionId = PKIXExtensions.SubjectDirectoryAttributes_Id;
		this.critical = critical.booleanValue();
		encodeThis();
	}	
	
	public SubjectDirectoryAttributesExtension(Boolean critical, Object value){
		
	}
		
	private void encodeThis() throws IOException{
		
		if(placeOfBirth == null || placeOfBirth.isEmpty()){
			this.extensionValue = null;
			return;
		}
		if(countryOfCitizenship == null || countryOfCitizenship.isEmpty()){
			this.extensionValue = null;
			return;
		}
		if(gender == null || gender.isEmpty()){
			this.extensionValue = null;
			return;
		}
		DerOutputStream os = new DerOutputStream();
		os.putGeneralString(placeOfBirth);
		os.putGeneralString(countryOfCitizenship);
		os.putGeneralString(gender);
		DerOutputStream izlaz = new DerOutputStream();
		izlaz.derEncode(os);
		this.extensionValue = izlaz.toByteArray();
	}
	
	public String toString(){
		String result = super.toString() + "SubjectDirectoryAttributes [\n";
		if(placeOfBirth != null && !placeOfBirth.isEmpty()){
			result += " " + placeOfBirth + "\n";
		}
		if(countryOfCitizenship != null && !countryOfCitizenship.isEmpty()){
			result += " " + countryOfCitizenship + "\n";
		}
		if(gender != null && !gender.isEmpty()){
			result += " " + gender + "\n";
		}
		result += "]\n";
		return result;
	}
	
	public void encode(OutputStream out) throws IOException{
		DerOutputStream tmp = new DerOutputStream();
		if(extensionValue == null){
			extensionId = PKIXExtensions.SubjectDirectoryAttributes_Id;
			critical = false;
			encodeThis();
		}
		super.encode(tmp);
		out.write(tmp.toByteArray());
	}

	@Override
	public void set(String name, Object o) throws CertificateException, IOException {
		if(name.equalsIgnoreCase(PLACE_OF_BIRTH)){
			if(!(o instanceof String)){
				throw new IOException("Attriute value should be of type String");
			}
			this.placeOfBirth = (String)o;
		}else if(name.equalsIgnoreCase(COUNTRY_OF_CITIZENSHIP)){
			if(!(o instanceof String)){
				throw new IOException("Attriute value should be of type String");
			}
			this.countryOfCitizenship = (String)o;
		}else if(name.equalsIgnoreCase(GENDER)){
			if(!(o instanceof String)){
				throw new IOException("Attriute value should be of type String");
			}
			this.gender = (String)o;
		}else{
			throw new IOException("Attribute name not recognized by CertAttrSet:SubjectDirectoryAttributes");
		}
		encodeThis();
	}

	@Override
	public Object get(String name) throws CertificateException, IOException {
		if(name.equalsIgnoreCase(PLACE_OF_BIRTH))
			return (placeOfBirth);
		else if(name.equalsIgnoreCase(COUNTRY_OF_CITIZENSHIP)){
			return (countryOfCitizenship);
		}else if(name.equalsIgnoreCase(GENDER)){
			return (gender);
		}else
			throw new IOException("Attribute name not recognized by CertAttrSet:SubjectDirectoryAttributes.");
	}

	@Override
	public void delete(String name) throws CertificateException, IOException {
		if(name.equalsIgnoreCase(PLACE_OF_BIRTH))
			placeOfBirth = null;
		else if(name.equalsIgnoreCase(COUNTRY_OF_CITIZENSHIP)){
			countryOfCitizenship = null;
		}else if(name.equalsIgnoreCase(GENDER)){
			gender = null;
		}else
			throw new IOException("Attribute name not recognized by CertAttrSet:SubjectDirectoryAttributes.");
		encodeThis();
	}

	@Override
	public Enumeration<String> getElements() {
		AttributeNameEnumeration elements = new AttributeNameEnumeration();
		elements.addElement(PLACE_OF_BIRTH);
		elements.addElement(COUNTRY_OF_CITIZENSHIP);
		elements.addElement(GENDER);
		return (elements.elements());
	}

	@Override
	public String getName() {
		return (NAME);
	}
	
}
