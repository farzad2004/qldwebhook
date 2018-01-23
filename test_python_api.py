import dropbox
import requests
import json
import PIL.Image

url = "https://api.dropboxapi.com/2/files/alpha/get_metadata"

headers = {
    "Authorization": "Bearer 8gR4PXP8kpAAAAAAAAMl4JDfkuEbadv0Gq8qWJay24-QyfSZgXR5B2Xx3yaxRIAa",
    "Content-Type": "application/json"
}

data = {
    "path": "/apps/test_api.jpg",
    "include_media_info": True,
    "include_deleted": True,
    "include_has_explicit_shared_members": True
}

r = requests.post(url, headers=headers, data=json.dumps(data))


dbx = dropbox.Dropbox('8gR4PXP8kpAAAAAAAAMl4JDfkuEbadv0Gq8qWJay24-QyfSZgXR5B2Xx3yaxRIAa')

dbx.users_get_current_account()
for entry in dbx.files_list_folder('/apps').entries:
    print(entry.name)


dbx.files_upload("Potential headline: Game 5 a nail-biter as Warriors inch out Cavs", '/cavs vs warriors/game 5/story.txt')

# OUTPUT:
# Cavs vs Warriors
x= dbx.files_get_metadata('/apps/test_api.jpg',include_media_info=True)
y= dropbox.files.MediaMetadata
print(x)


try:
	j = 'test_api.jpg'
	dbx.files_download_to_file(j,'/Apps/' + j)

	import PIL.ExifTags

	img = PIL.Image.open(j)

	exif = {
		PIL.ExifTags.TAGS[k]: v
		for k, v in img._getexif().items()
		if k in PIL.ExifTags.TAGS

	}
	for (k, v) in img._getexif().iteritems():
		print '%s = %s' % (PIL.ExifTags.get(k), v)

except dropbox.exceptions.ApiError, e:
	print('Error: %s' % (e,))
except Exception, e:
    print('Error: %s' % (e,))

print 'hi'