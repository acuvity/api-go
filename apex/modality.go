// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// Modality represents the model of a modality
type Modality struct {
	// The group of data.
	//
	// The current list can be obtained through the analyzers API by searching for
	// detector groups in the 'Modality' analyzer group.
	//
	// Example of group: application, archive, audio, code, document, executable, font,
	// image, text, unknown, video.
	Group string `json:"group" msgpack:"group" bson:"group" mapstructure:"group,omitempty"`

	// The type of data.
	//
	// The current list can be obtained through the analyzers API by searching for
	// detector names in the 'Modality' analyzer group.
	//
	// Example of type: 3dsm, 3gp, 3mf, ace, ada, ai, apk, applebplist, appleplist, ar,
	// arc, arj, asc, asf, asm, asp, au, autohotkey, autoit, avi, avif, awk, ax, batch,
	// bazel, bcad, bib, bmp, bpg, brainfuck, brf, bzip, bzip3, c, cab, cat, cdf, chm,
	// clojure, cmake, cobol, coff, coffeescript, com, cpl, cpp, crt, crx, cs, csproj,
	// css, csv, dart, deb, dex, dey, dicom, diff, django, dll, dm, dmg, dmigd,
	// dmscript, doc, dockerfile, docx, dotx, dwg, dxf, dylib, elf, elixir, emf, eml,
	// epub, erb, erlang, exe, flac, flv, fortran, fpx, gemfile, gemspec, gif,
	// gitattributes, gitmodules, gleam, go, gradle, groovy, gzip, h, h5, handlebars,
	// haskell, hcl, heif, hlp, hpp, hta, htaccess, html, hwp, icns, ico, ics,
	// ignorefile, ini, internetshortcut, ipynb, iso, jar, java, javabytecode,
	// javascript, jinja, jng, jnlp, jp2, jpeg, json, jsonl, jsx, julia, jxl, ko,
	// kotlin, latex, lha, license, lisp, lnk, lock, lua, lz, lz4, m3u, m4, macho,
	// makefile, markdown, matlab, mht, midi, mkv, mp3, mp4, mpegts, mscompress, msi,
	// msix, mui, mum, npy, npz, objectivec, ocaml, ocx, odex, odin, odp, ods, odt,
	// ogg, one, onnx, otf, outlook, pascal, pcap, pdb, pdf, pebin, pem, perl, php,
	// pickle, png, po, postscript, powershell, ppt, pptx, prolog, proteindb, proto,
	// psd, python, pythonbytecode, pytorch, qoi, qt, r, randomascii, rar, rdf, rlib,
	// rll, rpm, rst, rtf, ruby, rust, scala, scheme, scr, scss, sevenzip, sgml, shell,
	// smali, snap, so, solidity, sql, sqlite, squashfs, srt, stlbinary, stltext, sum,
	// svg, swf, swift, symlinktext, sys, tar, tcl, textproto, tga, thumbsdb, tiff,
	// toml, torrent, tsv, tsx, ttf, twig, txt, txtascii, txtutf16, txtutf8,
	// typescript, vba, vbe, vcxproj, verilog, vhdl, visio, vtt, vue, wad, wasm, wav,
	// webm, webp, webtemplate, winregistry, wma, wmf, wmv, woff, woff2, xar, xcf, xls,
	// xlsb, xlsx, xml, xpi, xz, yaml, yara, zig, zip, zlibstream, zst.
	Type string `json:"type" msgpack:"type" bson:"type" mapstructure:"type,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewModality returns a new *Modality
func NewModality() *Modality {

	return &Modality{
		ModelVersion: 1,
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Modality) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesModality{}

	s.Group = o.Group
	s.Type = o.Type

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Modality) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesModality{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.Group = s.Group
	o.Type = s.Type

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *Modality) BleveType() string {

	return "modality"
}

// DeepCopy returns a deep copy if the Modality.
func (o *Modality) DeepCopy() *Modality {

	if o == nil {
		return nil
	}

	out := &Modality{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Modality.
func (o *Modality) DeepCopyInto(out *Modality) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Modality: %s", err))
	}

	*out = *target.(*Modality)
}

// Validate valides the current information stored into the structure.
func (o *Modality) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("group", o.Group); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateRequiredString("type", o.Type); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if len(requiredErrors) > 0 {
		return requiredErrors
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// SpecificationForAttribute returns the AttributeSpecification for the given attribute name key.
func (*Modality) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := ModalityAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return ModalityLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Modality) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return ModalityAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Modality) ValueForAttribute(name string) any {

	switch name {
	case "group":
		return o.Group
	case "type":
		return o.Type
	}

	return nil
}

// ModalityAttributesMap represents the map of attribute for Modality.
var ModalityAttributesMap = map[string]elemental.AttributeSpecification{
	"Group": {
		AllowedChoices: []string{},
		BSONFieldName:  "group",
		ConvertedName:  "Group",
		Description: `The group of data.

The current list can be obtained through the analyzers API by searching for
detector groups in the 'Modality' analyzer group.

Example of group: application, archive, audio, code, document, executable, font,
image, text, unknown, video.`,
		Exposed:  true,
		Name:     "group",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
	"Type": {
		AllowedChoices: []string{},
		BSONFieldName:  "type",
		ConvertedName:  "Type",
		Description: `The type of data.

The current list can be obtained through the analyzers API by searching for
detector names in the 'Modality' analyzer group.

Example of type: 3dsm, 3gp, 3mf, ace, ada, ai, apk, applebplist, appleplist, ar,
arc, arj, asc, asf, asm, asp, au, autohotkey, autoit, avi, avif, awk, ax, batch,
bazel, bcad, bib, bmp, bpg, brainfuck, brf, bzip, bzip3, c, cab, cat, cdf, chm,
clojure, cmake, cobol, coff, coffeescript, com, cpl, cpp, crt, crx, cs, csproj,
css, csv, dart, deb, dex, dey, dicom, diff, django, dll, dm, dmg, dmigd,
dmscript, doc, dockerfile, docx, dotx, dwg, dxf, dylib, elf, elixir, emf, eml,
epub, erb, erlang, exe, flac, flv, fortran, fpx, gemfile, gemspec, gif,
gitattributes, gitmodules, gleam, go, gradle, groovy, gzip, h, h5, handlebars,
haskell, hcl, heif, hlp, hpp, hta, htaccess, html, hwp, icns, ico, ics,
ignorefile, ini, internetshortcut, ipynb, iso, jar, java, javabytecode,
javascript, jinja, jng, jnlp, jp2, jpeg, json, jsonl, jsx, julia, jxl, ko,
kotlin, latex, lha, license, lisp, lnk, lock, lua, lz, lz4, m3u, m4, macho,
makefile, markdown, matlab, mht, midi, mkv, mp3, mp4, mpegts, mscompress, msi,
msix, mui, mum, npy, npz, objectivec, ocaml, ocx, odex, odin, odp, ods, odt,
ogg, one, onnx, otf, outlook, pascal, pcap, pdb, pdf, pebin, pem, perl, php,
pickle, png, po, postscript, powershell, ppt, pptx, prolog, proteindb, proto,
psd, python, pythonbytecode, pytorch, qoi, qt, r, randomascii, rar, rdf, rlib,
rll, rpm, rst, rtf, ruby, rust, scala, scheme, scr, scss, sevenzip, sgml, shell,
smali, snap, so, solidity, sql, sqlite, squashfs, srt, stlbinary, stltext, sum,
svg, swf, swift, symlinktext, sys, tar, tcl, textproto, tga, thumbsdb, tiff,
toml, torrent, tsv, tsx, ttf, twig, txt, txtascii, txtutf16, txtutf8,
typescript, vba, vbe, vcxproj, verilog, vhdl, visio, vtt, vue, wad, wasm, wav,
webm, webp, webtemplate, winregistry, wma, wmf, wmv, woff, woff2, xar, xcf, xls,
xlsb, xlsx, xml, xpi, xz, yaml, yara, zig, zip, zlibstream, zst.`,
		Exposed:  true,
		Name:     "type",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
}

// ModalityLowerCaseAttributesMap represents the map of attribute for Modality.
var ModalityLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"group": {
		AllowedChoices: []string{},
		BSONFieldName:  "group",
		ConvertedName:  "Group",
		Description: `The group of data.

The current list can be obtained through the analyzers API by searching for
detector groups in the 'Modality' analyzer group.

Example of group: application, archive, audio, code, document, executable, font,
image, text, unknown, video.`,
		Exposed:  true,
		Name:     "group",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
	"type": {
		AllowedChoices: []string{},
		BSONFieldName:  "type",
		ConvertedName:  "Type",
		Description: `The type of data.

The current list can be obtained through the analyzers API by searching for
detector names in the 'Modality' analyzer group.

Example of type: 3dsm, 3gp, 3mf, ace, ada, ai, apk, applebplist, appleplist, ar,
arc, arj, asc, asf, asm, asp, au, autohotkey, autoit, avi, avif, awk, ax, batch,
bazel, bcad, bib, bmp, bpg, brainfuck, brf, bzip, bzip3, c, cab, cat, cdf, chm,
clojure, cmake, cobol, coff, coffeescript, com, cpl, cpp, crt, crx, cs, csproj,
css, csv, dart, deb, dex, dey, dicom, diff, django, dll, dm, dmg, dmigd,
dmscript, doc, dockerfile, docx, dotx, dwg, dxf, dylib, elf, elixir, emf, eml,
epub, erb, erlang, exe, flac, flv, fortran, fpx, gemfile, gemspec, gif,
gitattributes, gitmodules, gleam, go, gradle, groovy, gzip, h, h5, handlebars,
haskell, hcl, heif, hlp, hpp, hta, htaccess, html, hwp, icns, ico, ics,
ignorefile, ini, internetshortcut, ipynb, iso, jar, java, javabytecode,
javascript, jinja, jng, jnlp, jp2, jpeg, json, jsonl, jsx, julia, jxl, ko,
kotlin, latex, lha, license, lisp, lnk, lock, lua, lz, lz4, m3u, m4, macho,
makefile, markdown, matlab, mht, midi, mkv, mp3, mp4, mpegts, mscompress, msi,
msix, mui, mum, npy, npz, objectivec, ocaml, ocx, odex, odin, odp, ods, odt,
ogg, one, onnx, otf, outlook, pascal, pcap, pdb, pdf, pebin, pem, perl, php,
pickle, png, po, postscript, powershell, ppt, pptx, prolog, proteindb, proto,
psd, python, pythonbytecode, pytorch, qoi, qt, r, randomascii, rar, rdf, rlib,
rll, rpm, rst, rtf, ruby, rust, scala, scheme, scr, scss, sevenzip, sgml, shell,
smali, snap, so, solidity, sql, sqlite, squashfs, srt, stlbinary, stltext, sum,
svg, swf, swift, symlinktext, sys, tar, tcl, textproto, tga, thumbsdb, tiff,
toml, torrent, tsv, tsx, ttf, twig, txt, txtascii, txtutf16, txtutf8,
typescript, vba, vbe, vcxproj, verilog, vhdl, visio, vtt, vue, wad, wasm, wav,
webm, webp, webtemplate, winregistry, wma, wmf, wmv, woff, woff2, xar, xcf, xls,
xlsb, xlsx, xml, xpi, xz, yaml, yara, zig, zip, zlibstream, zst.`,
		Exposed:  true,
		Name:     "type",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
}

type mongoAttributesModality struct {
	Group string `bson:"group"`
	Type  string `bson:"type"`
}
