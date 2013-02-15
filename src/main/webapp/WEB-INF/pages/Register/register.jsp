<%--~
  ~ JBoss, Home of Professional Open Source
  ~ Copyright Red Hat, Inc., and individual contributors
  ~ by the @authors tag. See the copyright.txt in the distribution for a
  ~ full listing of individual contributors.
  ~
  ~ Licensed under the Apache License, Version 2.0 (the "License");
  ~ you may not use this file except in compliance with the License.
  ~ You may obtain a copy of the License at
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~ Unless required by applicable law or agreed to in writing, software
  ~ distributed under the License is distributed on an "AS IS" BASIS,
  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ~ See the License for the specific language governing permissions and
  ~ limitations under the License.
  --%>

<jsp:include page="../../template/barcode_header.jsp" />
<%@page pageEncoding="UTF-8" %>
<div class="container">
    <div class="sixteen columns">
        <h1 class="remove-bottom" style="margin-top: 40px">Logged in</h1>
        <hr />
    </div>
    <div class="sixteen columns">
        <p>maybe you should try the <a href="delorean">delorean page</a></p>
        <p>you can also try the <a href="admin">restricted admin page</a></p>
        hello ${aeroGearUser.username} to the authentication page!
        <p> <a href="logout">Logout</a></p>
    </div>
    <div class="sixteen columns">
        <h2>Google authenticator</h2>
        <hr />
        <p><strong>Note:</strong> <em>If you have already scanned the QRCode, is not necessary to do it again</em></p>
        <h5><a href="#" id="qrcode" >Give it a try!</a></h5>
        <div id="qrcode-div"></div>
        <form action="otp" method="post">
            <label>OTP:</label>
            <input autocomplete="off" type="password" name="aeroGearUser.otp"/>
            <input type="submit"/>
        </form>
    </div>
</div>
<jsp:include page="../../template/footer.jsp" />