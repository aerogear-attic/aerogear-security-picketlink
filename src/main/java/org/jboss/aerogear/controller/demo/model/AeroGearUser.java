/**
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.aerogear.controller.demo.model;

/**
 * A simple POJO User entity to support the most widely-used authentication mechanism
 */

public class AeroGearUser {

    private String username;
    private String firstName;
    private String otp;
    private String password;
    private String email;
    private String lastName;
    private String uri;

    /**
     * URI retrieval
     *
     * @return OTP URI encoded in QRCode. For example: otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP
     */
    public String getUri() {
        return uri;
    }

    /**
     * Provision a OTP URI
     *
     * @param uri OTP URI encoded in QRCode. For example: otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP
     */
    public void setUri(String uri) {
        this.uri = uri;
    }

    /**
     * Username retrieval
     *
     * @return username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Username setup
     *
     * @param username username
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * First name retrieval
     *
     * @return first name
     */
    public String getFirstName() {
        return firstName;
    }

    /**
     * First name setup
     *
     * @param firstName first name
     */
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    /**
     * OTP provided on login
     *
     * @return OTP
     */
    public String getOtp() {
        return otp;
    }

    /**
     * OTP provided on login
     *
     * @param otp OTP
     */
    public void setOtp(String otp) {
        this.otp = otp;
    }

    /**
     * Password provided on login
     *
     * @return Password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Password provided on login
     *
     * @param password Password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * E-mail provided on registration process
     *
     * @param email E-mail
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * E-mail provided on registration process
     *
     * @return E-mail
     */
    public String getEmail() {
        return email;
    }

    /**
     * Last name provided on registration process
     *
     * @param lastName Last name
     */
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    /**
     * Last name provided on registration process
     *
     * @return Last name
     */
    public String getLastName() {
        return lastName;
    }
}