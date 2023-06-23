# 2cUTC_dissectors

A set of Wireshark .lua scripts to dissect 2cUTC CTRACEs

**INSTALL**

_FIRST_

copy these luas to `C:\Users\<username>\AppData\Roaming\Wireshark\plugins`

_THEN EITHER_

Go to WireShark / Options / Protocols and select DLT-USER - Add an entry to the table  with DLT=147.
In this entry, set Payload Protocol to "2cutc", set Header Size to 0, Header Protocol to empty, Trailer Size to 0, and Trailer Protocol to empty

_OR_

For these dissectors to be used create (or edit) a file [user_dlts] in your wirshark profile and create (or add) an entry with the following contents:

```lua
# This file is automatically generated, DO NOT MODIFY.
"User 0 (DLT=147)","2cutc","0","","0",""
```

**EXAMPLE COLORING RULE**

Since all aspects of the lua dissectors are available as fields, it is easy to produce a single coloring rule to hilight
trace records that are considered dertrimental:

```
# This file was created by Wireshark. Edit with care.
@SYSTCPIP Bad ENTID@2cutc.component == "SYSTCPIP" && systcpip.flag == "!"@[65535,21845,0][65535,65535,65535]
```

**EXAMPLE FILTER STATEMENT**

In a similar way to coloring rules, you may use the fields for filtering the trace records.

```
2cutc.component == "SYSTCPIP" && systcpip.flag == "!"
```

**SPECIAL FIELD "2cutc.info"**

This field is "created" and "filled" by the 2cutc POST-DISSECTOR.

Here's how this works:

Any upper dissector may have fields that can be used to indicate special information. The post-dissector can be used to access these fields and can then decide to populate the "2cutc.info" field, which is initially empty.

You may make the `2cutc.info` field visible in the trace by defining a _(new)_ custom column using `2cutc.info` as field name.

**NOTES**

You can now access fields like "2cutc.info", "systcpip.option" and others from the coloring syntax, the filtering syntax and also when defining columns to display.

You can derive the available fields by looking at the INIT section of the lua dissectors (and post-dissectors) supplied here.
