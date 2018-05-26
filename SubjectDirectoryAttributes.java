/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import java.io.Serializable;

/**
 *
 * @author Milutinac
 */
public class SubjectDirectoryAttributes implements Serializable{
	private String dateOfBirth;
	private String placeOfBirth;
	private String countryOfCitizenship;
	private String gender;
	
	public static final String OID = "2.5.29.9";

	public SubjectDirectoryAttributes(String dateOfBirth, String placeOfBirth, String countryOfCitizenship, String gender) {
		this.dateOfBirth = dateOfBirth;
		this.placeOfBirth = placeOfBirth;
		this.countryOfCitizenship = countryOfCitizenship;
		this.gender = gender;
	}

	public String getDateOfBirth() {
		return dateOfBirth;
	}

	public void setDateOfBirth(String dateOfBirth) {
		this.dateOfBirth = dateOfBirth;
	}

	public String getPlaceOfBirth() {
		return placeOfBirth;
	}

	public void setPlaceOfBirth(String placeOfBirth) {
		this.placeOfBirth = placeOfBirth;
	}

	public String getCountryOfCitizenship() {
		return countryOfCitizenship;
	}

	public void setCountryOfCitizenship(String countryOfCitizenship) {
		this.countryOfCitizenship = countryOfCitizenship;
	}

	public String getGender() {
		return gender;
	}

	public void setGender(String gender) {
		this.gender = gender;
	}
	
}
