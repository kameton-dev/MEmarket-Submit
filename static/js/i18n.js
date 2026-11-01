(function() {
    const script = document.currentScript;
    const localeUrl = script.dataset.localeUrl;
    const page = document.documentElement.dataset.i18nPage;
    const textOriginals = new WeakMap();
    const attributeOriginals = new WeakMap();
    let messages = {};
    let localeRequest = 0;

    function pageMessages() {
        return messages[page] || {};
    }

    function translate(key, values) {
        const sharedMessages = messages.shared || {};
        const text = pageMessages()[key] || sharedMessages[key] || key;
        return Object.entries(values || {}).reduce(function(result, entry) {
            return result.replace('{' + entry[0] + '}', entry[1]);
        }, text);
    }

    function lookupString(value) {
        const currentPage = pageMessages();
        const sharedMessages = messages.shared || {};
        const pageStrings = currentPage.strings || {};
        const sharedStrings = sharedMessages.strings || {};
        const exact = pageStrings[value] || sharedStrings[value];
        if (exact) return exact;
        const prefixes = Object.assign({}, sharedStrings, pageStrings);
        const prefix = Object.keys(prefixes).find(function(key) {
            if (key.endsWith(' ')) return value.startsWith(key.trim() + ' ');
            return key.endsWith('(') && value.startsWith(key);
        });
        if (!prefix) return undefined;
        return prefixes[prefix] + value.slice(prefix.length);
    }

    function translateMessage(text) {
        return lookupString(text) || text;
    }

    function applyTranslations() {
        document.querySelectorAll('[data-i18n]').forEach(function(element) {
            const values = {};
            ['number', 'publisher'].forEach(function(name) {
                const value = element.getAttribute('data-i18n-' + name);
                if (value !== null) values[name] = value;
            });
            element.textContent = translate(element.dataset.i18n, values);
        });
        document.querySelectorAll('[data-i18n-message]').forEach(function(element) {
            element.textContent = translateMessage(element.dataset.i18nMessage);
        });
        const uploadStatus = document.getElementById('upload-status');
        if (uploadStatus && uploadStatus.dataset.selectedFilename) {
            uploadStatus.textContent = translate('fileSelected', {
                filename: uploadStatus.dataset.selectedFilename
            });
        }

        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        let textNode;
        while ((textNode = walker.nextNode())) {
            if (textNode.parentElement.closest('script, style, textarea, code, pre')) continue;
            if (!textOriginals.has(textNode)) textOriginals.set(textNode, textNode.nodeValue);
            const original = textOriginals.get(textNode);
            const translated = lookupString(original.trim());
            if (translated) {
                const leading = original.match(/^\s*/)[0];
                const trailing = original.match(/\s*$/)[0];
                textNode.nodeValue = leading + translated + trailing;
            } else if (document.documentElement.lang === 'ru') {
                textNode.nodeValue = original;
            }
        }

        document.querySelectorAll(
            '[data-i18n-placeholder], [data-i18n-alt], [data-i18n-aria-label]'
        )
            .forEach(function(element) {
                ['placeholder', 'alt', 'aria-label'].forEach(function(attribute) {
                    const key = element.dataset['i18n' + attribute.split('-').map(function(part) {
                        return part.charAt(0).toUpperCase() + part.slice(1);
                    }).join('')];
                    if (key) {
                        element.setAttribute(attribute, translate(key, {
                            number: element.dataset.i18nNumber || ''
                        }));
                    }
                });
            });

        document.querySelectorAll('[data-i18n-category]').forEach(function(element) {
            const categories = (messages.shared || {}).categories || {};
            const category = element.dataset.i18nCategory;
            if (categories[category]) element.textContent = categories[category];
        });

        document.querySelectorAll('[alt], [placeholder], [aria-label], [title]').forEach(function(element) {
            ['alt', 'placeholder', 'aria-label', 'title'].forEach(function(attribute) {
                if (!element.hasAttribute(attribute)) return;
                const i18nAttribute = 'i18n' + attribute.split('-').map(function(part) {
                    return part.charAt(0).toUpperCase() + part.slice(1);
                }).join('');
                if (element.dataset[i18nAttribute]) return;
                let originals = attributeOriginals.get(element);
                if (!originals) {
                    originals = {};
                    attributeOriginals.set(element, originals);
                }
                if (!(attribute in originals)) originals[attribute] = element.getAttribute(attribute);
                const translated = lookupString(originals[attribute].trim());
                if (translated) {
                    element.setAttribute(attribute, translated);
                } else if (document.documentElement.lang === 'ru') {
                    element.setAttribute(attribute, originals[attribute]);
                }
            });
        });

        document.querySelectorAll('head title[data-i18n]').forEach(function(element) {
            element.textContent = translate(element.dataset.i18n, {
                app: element.dataset.i18nApp || ''
            });
        });
        const markdownPreview = document.getElementById('markdown-preview');
        const markdownToggle = document.getElementById('markdown-preview-toggle');
        if (markdownPreview && markdownToggle && !markdownPreview.hidden) {
            markdownToggle.textContent = translate('hidePreview');
        }
    }

    async function applyLocale(locale) {
        if (!['ru', 'en'].includes(locale)) locale = 'ru';
        const requestId = ++localeRequest;
        const response = await fetch(localeUrl.replace(/ru\.json$/, locale + '.json'));
        if (!response.ok) {
            throw new Error('Could not load locale "' + locale + '": ' + response.status);
        }
        const newMessages = await response.json();
        if (requestId !== localeRequest) return;
        messages = newMessages;
        document.documentElement.lang = locale;
        applyTranslations();
        const selector = document.getElementById('language-select');
        if (selector) selector.value = locale;
        localStorage.setItem('site-language', locale);
        window.dispatchEvent(new CustomEvent('localechange', { detail: { locale: locale } }));
    }

    window.translate = translate;
    window.translateMessage = translateMessage;
    window.applyTranslations = applyTranslations;
    window.applyLocale = applyLocale;

    document.addEventListener('DOMContentLoaded', function() {
        const selector = document.getElementById('language-select');
        if (selector) {
            selector.addEventListener('change', function() {
                applyLocale(this.value).catch(function(error) {
                    console.error(error);
                });
            });
        }
        applyLocale(localStorage.getItem('site-language') || 'ru').catch(function(error) {
            console.error(error);
        });
    });
})();
